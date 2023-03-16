#!/usr/bin/env python3
#
# MIT License
#
# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
"""
This is the main entry point for Cray ipxe. The Cray iPXE service is a state
engine used to create and deploy ipxe binaries within the management plane.

iPXE binaries need to be regenerated throughout the lifetime of the Cray system
as a result of changes in requested build configuration, updates to the service,
and updates provided by the cluster certificate creation setup roles.

In response to changes in these configuration pieces, new ipxe binaries are
issued by this service. The resultant artifacts are placed into the tftp cephfs
share location.
"""

import fileinput
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

import jwt
import oauthlib.oauth2
import requests_oauthlib
from crayipxe.liveness.ipxe_timestamp import ipxeTimestamp, IPXE_PATH, DEBUG_IPXE_PATH
from kubernetes import client, config
from yaml import safe_load, safe_dump

IPXE_BUILD_DIR = '/ipxe'
TFTP_MOUNT_DIR = '/shared_tftp'
TOKEN_HOST = "api-gw-service-nmn.local"  # default in case it is not in the settings configmap
LOGGER = logging.getLogger(__name__)

CRAY_IPXE_SETTINGS_CONFIGMAP_NAME = 'cray-ipxe-settings'
CRAY_IPXE_SETTINGS_CONFIGMAP_NAMESPACE = 'services'
CRAY_IPXE_SETTINGS_CONFIGMAP_SETTINGS_YAML = 'settings.yaml'

# These iPxe debug settings are enabled in normal builds because they provide
# useful info (i.e: BIOS timme and basic http info).
cray_ipxe_standard_opts = "httpcore,x509,efi_time"

# These settings are enabled by default when a debug build is requested
# ('cray_ipxe_build_debug=true') unless they are overridden in the settings
# (via 'cray_ipxe_build_debug_level').
cray_ipxe_debug_level_default = "httpcore:2,x509:2,efi_time"

# The minimum amount of time in seconds prior to the expiration time for which
# a JWT token is still considered valid for use by this service.
token_min_remaining_valid_time_default = 30 * 60
cray_ipxe_token_min_remaining_valid_time = token_min_remaining_valid_time_default

DEFAULT_IPXE_BINARY_NAME = 'ipxe.efi'
DEFAULT_IPXE_DEBUG_BINARY_NAME = 'debug-ipxe.efi'
CRAY_IPXE_BINARY_NAME = 'cray_ipxe_binary_name'
CRAY_IPXE_DEBUG_BINARY_NAME = 'cray_ipxe_debug_binary_name'
CRAY_IPXE_BINARY_NAME_ACTIVE = 'cray_ipxe_binary_name_active'
CRAY_IPXE_DEBUG_BINARY_NAME_ACTIVE = 'cray_ipxe_debug_binary_name_active'


class GracefulExit(object):
    """
    Registers graceful behavior in the event of termination signals.
    """
    kill_now = False

    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        self.kill_now = True
        LOGGER.info("Job is quitting, cleaning up.")
        self.func(*self.args, **self.kwargs)
        LOGGER.info("Cleaned up!")


def cleanup(*args, **kwargs):
    """
    The behavior we'd like to execute at time of shutdown.
    """
    pass


def create_binaries(api_instance, fname, script, cert=None, arch='x86_64', kind='efi',
                    bearer_token=None, ipxe_build_debug=False, ipxe_build_debug_level=None):
    """
    Creates a new ipxe binary and registers it to the TFTP service for
    consumption.
    """
    LOGGER.info('create_binaries called for %s, %s' % (kind, arch))

    # Aggregate a build command
    build_command = ['make']

    # Defined build behavior translation
    build_strings = {('x86_64', 'efi'): 'bin-x86_64-efi/ipxe.efi',
                     ('x86_64', 'kpxe'): 'bin/undionly.kpxe'}

    # Add architecture specific flags
    try:
        build_cmd = build_strings[(arch, kind)]
        build_dest = os.path.join(IPXE_BUILD_DIR, build_cmd)
        product_dest = os.path.join(TFTP_MOUNT_DIR, fname)
        build_command.append(build_cmd)
        if ipxe_build_debug:
            # Enabling the debug build will include options defined in
            # ipxe_build_debug_level which can be a default set of options
            # or can be customized by settings.
            build_command.append('DEBUG=%s' % ipxe_build_debug_level)
        else:
            # By default a build will include some minimal debug options.
            build_command.append('DEBUG=%s' % cray_ipxe_standard_opts)
    except KeyError:
        raise Exception("Unsupported build type: arch '%s' of kind '%s'." % (arch, kind))

    # Determine the S3 host name and pass this to the iPxe build.  If the hostname
    # can not be determined then the default value for S3_HOST will be used as
    # defined in the ipxe makefile.
    try:
        LOGGER.info("Attempting to obtain S3_HOST from cm/sts-rados-config int_endpoint_url")
        sts_rados_raw = api_instance.read_namespaced_config_map('sts-rados-config', 'services')
        sts_rados_conf = safe_load(sts_rados_raw.data['rados_conf'])
        sts_rados_internal_endpoint = sts_rados_conf.get('int_endpoint_url')
        parsed_uri = urlparse(sts_rados_internal_endpoint)
        rgw_s3_host = parsed_uri.hostname
        if rgw_s3_host:
            # Override the default S3_HOST ipxe makefile parameter value.
            LOGGER.info("Setting make param S3_HOST=%s" % rgw_s3_host)
            build_command.append('S3_HOST=%s' % rgw_s3_host)
        else:
            LOGGER.error("Unable to set S3_HOST: Missing or empty int_endpoint_url")
    except KeyError as kex:
        LOGGER.error("Error reading the sts-rados-config map.  Unable to override S3_HOST")
        LOGGER.error("The specific error was: %s" % kex)
    except client.rest.ApiException as rex:
        LOGGER.error("Error getting the sts-rados-config map.  Unable to override S3_HOST")
        LOGGER.error("The specific error was: %s" % rex)

    if cert:
        # Write our cluster issued certificate to disk for build
        tfile = tempfile.NamedTemporaryFile(suffix='_cert', dir=IPXE_BUILD_DIR, delete=False)
        with open(tfile.name, 'w') as certfile:
            cert_path = tfile.name
            certfile.write(cert)
        build_command.append('CERT=%s' % (os.path.basename(cert_path)))
        build_command.append('TRUST=%s' % (os.path.basename(cert_path)))

        # Modify the configuration file to enable the HTTPS protocol in our build
        config_file = "/ipxe/config/general.h"
        tfile_original = tempfile.NamedTemporaryFile(suffix='_original', delete=False)
        shutil.copyfile(config_file, tfile_original.name)
        with open(config_file, "w") as fout:
            for line in fileinput.input([tfile_original.name]):
                fout.write(re.sub('#undef[ \t]+DOWNLOAD_PROTO_HTTPS',
                                  '#define DOWNLOAD_PROTO_HTTPS', line))

    # Write our build script to disk in a unique filename
    tfile = tempfile.NamedTemporaryFile(suffix='_script', dir=IPXE_BUILD_DIR, delete=False)
    with open(tfile.name, 'w') as ntf:
        ntf.write(script)
        script_path = ntf.name
    build_command.append('EMBED=%s' % (tfile.name))

    if bearer_token:
        LOGGER.info('Compiling with BEARER_TOKEN=%s' % (bearer_token))
        build_command.append('BEARER_TOKEN=%s' % (bearer_token))

    # Build it out
    LOGGER.info("Running command: %s" % (build_command))
    subprocess.check_call(build_command)
    LOGGER.info("Build completed.")

    # Move binary into place
    shutil.move(build_dest, product_dest)

    # Finally, we can remove the script we wrote to the build directory
    os.unlink(script_path)
    if cert:
        os.unlink(cert_path)
        shutil.copyfile(tfile_original.name, config_file)
        os.unlink(tfile_original.name)

    LOGGER.info("Newly created ipxe binary created: '%s'" % (product_dest))
    return product_dest


def fetch_token(token_host):
    # The token will be fetched from Keycloak using the client id and secret
    # from the mounted Kubernetes secret.
    token_url = "https://%s/keycloak/realms/shasta/protocol/openid-connect/token" % token_host
    auth_user_file = "/client_auth/client-id"
    auth_secret_file = "/client_auth/client-secret"
    oauth_client_id = ""
    oauth_client_secret = ""
    f = None
    try:
        f = open(auth_user_file, 'r')
        oauth_client_id = f.readline().rstrip()
    except IOError:
        LOGGER.error("Unable to read user name from %s", auth_user_file)
        return None
    finally:
        if f:
            f.close()
            f = None
    try:
        f = open(auth_secret_file, 'r')
        oauth_client_secret = f.readline().rstrip()
    except IOError:
        LOGGER.error("Unable to read secret from %s", auth_secret_file)
        return None
    finally:
        if f:
            f.close()
            f = None

    oauth_client = oauthlib.oauth2.BackendApplicationClient(
        client_id=oauth_client_id)

    session = requests_oauthlib.OAuth2Session(
        client=oauth_client, auto_refresh_url=token_url,
        auto_refresh_kwargs={
            'client_id': oauth_client_id,
            'client_secret': oauth_client_secret,
        },
        token_updater=lambda t: None)

    # Set the CA Cert file location so that we can use TLS to talk with Keycloak.
    # This certificate is mounted from an existing configmap.
    session.verify = "/ca_public_key/certificate_authority.crt"

    token = session.fetch_token(token_url=token_url, client_id=oauth_client_id,
                                client_secret=oauth_client_secret, timeout=500)

    access_token = None
    if token:
        access_token = token.get("access_token")
        if (access_token is not None):
            LOGGER.debug("Got access_token %s", access_token)
            return access_token
        else:
            LOGGER.error("Unable to get an access_token for client %s",
                         oauth_client_id)
            return None
    else:
        LOGGER.error("Unable to get a token object for client %s",
                     oauth_client_id)
        return None


def token_expiring_soon(bearer_token, min_remaining_valid_time):
    if bearer_token is None:
        return True

    # Just decode the token to extract the value.  THe token has already been
    # obtained from Keycloak here and verification gets handled
    # by the API GW when the token is checked.
    tokenMap = None
    try:
        tokenMap = jwt.decode(bearer_token,
                              options={"verify_signature": False})
    except Exception as ex:
        LOGGER.error("Unable to decode JWT.  Error was %s", ex)
        return True

    # Grab the expiration time
    tokenExp = tokenMap.get('exp')
    LOGGER.debug("JWT expiration time=%s" % tokenExp)

    if tokenExp is None:
        LOGGER.error("Unable to extract the expiration 'exp' from the JWT.")
        return True

    # If the current time is at or beyond the token expiration minus an
    # additional buffer time (to allow for a successful boot if used now)
    # then consider this token expiration time too close to expiration
    # and signal that we should request a new token.  The buffer time is
    # configurable but a default is provided if needed.
    tnow = int(time.time())
    tmax = tokenExp - min_remaining_valid_time
    LOGGER.debug("tnow=%s tmax=%s" % (tnow, tmax))
    if tnow >= tmax:
        LOGGER.debug("Detected that JWT will expire soon and needs updating.")
        return True
    else:
        LOGGER.debug("""The current JWT expiration time is acceptable. \
A new JWT will not be requested.""")
        return False


def read_ipxe_config(api_instance):
    return safe_load(api_instance.read_namespaced_config_map(CRAY_IPXE_SETTINGS_CONFIGMAP_NAME,
                                                             CRAY_IPXE_SETTINGS_CONFIGMAP_NAMESPACE).data[
                         CRAY_IPXE_SETTINGS_CONFIGMAP_SETTINGS_YAML])


def update_ipxe_config_binaries(api_instance, ipxe_binary_name, ipxe_debug_binary_name):
    LOGGER.info("Updating cray-ipxe-settings configmap: '%s' '%s'", ipxe_binary_name, ipxe_debug_binary_name)
    try:
        cray_ipxe_settings = read_ipxe_config(api_instance)
        cray_ipxe_settings[CRAY_IPXE_BINARY_NAME_ACTIVE] = ipxe_binary_name
        cray_ipxe_settings[CRAY_IPXE_DEBUG_BINARY_NAME_ACTIVE] = ipxe_debug_binary_name
        body = {'data': {CRAY_IPXE_SETTINGS_CONFIGMAP_SETTINGS_YAML: safe_dump(cray_ipxe_settings)}}
        api_instance.patch_namespaced_config_map(CRAY_IPXE_SETTINGS_CONFIGMAP_NAME,
                                                 CRAY_IPXE_SETTINGS_CONFIGMAP_NAMESPACE,
                                                 body)

    except client.rest.ApiException as e:
        LOGGER.info("Exception when updating cray-ipxe-settings configmap: %s\n", e)


def main():
    # Load Configuration and indicate initial health
    try:
        config.load_incluster_config()
    except Exception:
        sys.exit("This application must be run within the k8s cluster.")

    api_instance = client.CoreV1Api()

    # Initialize watched variables to none
    settings = None
    bss_script = None
    shell_script = None
    ca_public_key = None
    bearer_token = None
    ipxe_binary = None
    ipxe_debug_binary = None

    # Create a graceful exit semaphore
    run_context = GracefulExit(cleanup)

    # Patch the ipxe code after saving off the original first
    # This is patch is necessary, so that ipxe will handle the '+'
    # as part of a URI query.
    # Reference: http://lists.ipxe.org/pipermail/ipxe-devel/2015-May/004200.html
    uri_file = "/ipxe/core/uri.c"
    copy_file = "/ipxe/core/uri.original.c"
    try:
        shutil.copyfile(uri_file, copy_file)
    except shutil.Error:
        LOGGER.error("FAILED attempting to copy {} to {}".format(uri_file, copy_file))
        raise
    with open(uri_file, "w") as fout:
        for line in fileinput.input([copy_file]):
            fout.write(re.sub(r'^(\s*\[URI_QUERY\]\s*=\s*"#:@\?.*)("\s*,.*\n)', r'\1+\2', line))

    # Indefinitely monitor and respond to changes in our configuration
    LOGGER.info("Monitoring associated configmaps for related changes...")
    while not run_context.kill_now:
        # Examine service settings
        update_active_binaries = False
        settings_new = read_ipxe_config(api_instance)

        # The 'active' keys are automatically updated and should not be
        # considered when trying to determine if the configmap changed.
        # If they are not removed, this code will see a config change
        # after the 'active' keys are updated, causing the code to build
        # the ipxe binaries a second time unnecessarily.
        settings_new.pop(CRAY_IPXE_BINARY_NAME_ACTIVE, None)
        settings_new.pop(CRAY_IPXE_DEBUG_BINARY_NAME_ACTIVE, None)

        LOGGER.debug('settings_new=%s' % (str(settings_new)))
        if settings_new != settings:
            settings_changed = True
            settings = settings_new
            LOGGER.info("New cray-ipxe-settings settings detected: %s",
                        settings)

        # Nothing to build, so do not bother checking if anything else has changed
        if not settings['cray_ipxe_build_x86']:
            time.sleep(30)
            continue

        ipxe_binary_name = settings.get(CRAY_IPXE_BINARY_NAME, DEFAULT_IPXE_BINARY_NAME)
        ipxe_debug_binary_name = settings.get(CRAY_IPXE_DEBUG_BINARY_NAME, DEFAULT_IPXE_DEBUG_BINARY_NAME)

        # Enable debug logging for the httpcore ipxe module if debug has been
        # requested in the configmap.  This is very useful for seeing the
        # request and response details.
        ipxe_build_debug = False
        cray_ipxe_debug_level = ""
        cray_ipxe_build_debug = settings.get('cray_ipxe_build_debug')
        if cray_ipxe_build_debug is not None:
            if str(settings.get('cray_ipxe_build_debug')).upper() == "TRUE":
                LOGGER.debug('cray_ipxe_build_debug=TRUE')
                ipxe_build_debug = True

                cray_ipxe_debug_level = settings.get('cray_ipxe_build_debug_level')
                if cray_ipxe_debug_level is None:
                    cray_ipxe_debug_level = cray_ipxe_debug_level_default
                LOGGER.debug('cray_ipxe_build_debug_level=%s' % cray_ipxe_debug_level)

        # Setup token minimum remaining valid time.
        min_val_time = settings.get('cray_ipxe_token_min_remaining_valid_time')
        if min_val_time is not None:
            cray_ipxe_token_min_remaining_valid_time = min_val_time
        else:
            cray_ipxe_token_min_remaining_valid_time = token_min_remaining_valid_time_default
        LOGGER.debug('cray_ipxe_token_min_remaining_valid_time=%s'
                     % cray_ipxe_token_min_remaining_valid_time)

        # Obtain CA public key
        ca_public_key_raw = api_instance.read_namespaced_config_map(
            'cray-configmap-ca-public-key', 'services')
        ca_public_key_new = ca_public_key_raw.data['certificate_authority.crt']
        if ca_public_key_new != ca_public_key:
            ca_public_key_changed = True
            ca_public_key = ca_public_key_new

        # Conditionally set the cert to use with the build process
        if settings['cray_ipxe_build_with_cert']:
            public_cert = ca_public_key
        else:
            public_cert = None

        # Obtain the bearer token if one is provided in the configmap
        token_host = settings.get('cray_ipxe_token_host', TOKEN_HOST)
        bearer_token_changed = False

        if bearer_token is None:
            bearer_token_new = fetch_token(token_host)
        elif token_expiring_soon(bearer_token, cray_ipxe_token_min_remaining_valid_time):
            bearer_token_new = fetch_token(token_host)

        if bearer_token_new != bearer_token:
            bearer_token_changed = True
            bearer_token = bearer_token_new

            # Touch the relevant source to force a recompile.
            os.utime('/ipxe/net/tcp/httpcore.c', None)

        # ipxe script setting
        bss_script_raw = api_instance.read_namespaced_config_map('cray-ipxe-bss-ipxe', 'services')
        bss_script_new = bss_script_raw.data['bss.ipxe']

        # ipxe binary type and architecture settings...
        build_arch = settings.get('cray_ipxe_build_arch', 'x86_64')
        build_kind = settings.get('cray_ipxe_build_kind', 'efi')

        if bss_script_new != bss_script:
            bss_script_changed = True
            bss_script = bss_script_new
            LOGGER.info("New cray-ipxe-bss-ipxe script detected: %s",
                        bss_script)

        if any([settings_changed, ca_public_key_changed, bss_script_changed,
                bearer_token_changed]):
            # Create a file to indicate the build is in progress. A Kubernetes
            # livenessProbe can check on this file to see if it has stayed around
            # longer than expected, which would indicate a build failure.
            ipxe_timestamp = ipxeTimestamp(IPXE_PATH, os.getenv('IPXE_BUILD_TIME_LIMIT', 40))

            new_ipxe_binary = create_binaries(api_instance, ipxe_binary_name, bss_script, cert=public_cert,
                                              bearer_token=bearer_token,
                                              ipxe_build_debug=ipxe_build_debug,
                                              ipxe_build_debug_level=cray_ipxe_debug_level,
                                              arch=build_arch, kind=build_kind)

            if not ipxe_binary == new_ipxe_binary:
                if ipxe_binary and os.path.exists(ipxe_binary):
                    try:
                        # The ipxe binary name has changed. Remove the old binary.
                        LOGGER.info(f'Removing previous ipxe binary {ipxe_binary}')
                        os.remove(ipxe_binary)
                    except IOError:
                        LOGGER.warning(f'Could not remove previous ipxe binary {ipxe_binary}')
                update_active_binaries = True
                ipxe_binary = new_ipxe_binary

            ipxe_timestamp.delete()

        # ipxe shell settings
        shell_script_raw = api_instance.read_namespaced_config_map(
            'cray-ipxe-shell-ipxe', 'services')
        shell_script_new = shell_script_raw.data['shell.ipxe']
        if shell_script_new != shell_script:
            shell_script_changed = True
            shell_script = shell_script_new
        if any([settings_changed, ca_public_key_changed, shell_script_changed,
                bearer_token_changed]):
            # Create a file to indicate the build is in progress. A Kubernetes
            # livenessProbe can check on this file to see if it has stayed around
            # longer than expected, which would indicate a build failure.
            debug_ipxe_timestamp = ipxeTimestamp(DEBUG_IPXE_PATH,
                                                 os.getenv('DEBUG_IPXE_BUILD_TIME_LIMIT', 40))

            new_ipxe_debug_binary = create_binaries(api_instance, ipxe_debug_binary_name, shell_script,
                                                    cert=public_cert,
                                                    bearer_token=bearer_token,
                                                    ipxe_build_debug=ipxe_build_debug,
                                                    ipxe_build_debug_level=cray_ipxe_debug_level,
                                                    arch=build_arch, kind=build_kind)

            # The upgrade to cms-ipxe 1.10.0 changed the default name, potentially leaving an old file
            # This file still contains a valid token and should be cleaned up if not in use
            cruft_ipxe_debug_binary = os.path.join(TFTP_MOUNT_DIR, 'debug.efi')
            if ipxe_debug_binary != cruft_ipxe_debug_binary and new_ipxe_debug_binary != cruft_ipxe_debug_binary:
                if os.path.exists(cruft_ipxe_debug_binary):
                    try:
                        LOGGER.info(f'Removing old ipxe debug binary {cruft_ipxe_debug_binary}')
                        os.remove(cruft_ipxe_debug_binary)
                    except IOError:
                        LOGGER.warning(f'Could not remove old ipxe debug binary {cruft_ipxe_debug_binary}')

            if not ipxe_debug_binary == new_ipxe_debug_binary:
                if ipxe_debug_binary and os.path.exists(ipxe_debug_binary):
                    try:
                        # The ipxe debug binary name has changed. Remove the old binary.
                        LOGGER.info(f'Removing previous ipxe debug binary {ipxe_debug_binary}')
                        os.remove(ipxe_debug_binary)
                    except IOError:
                        LOGGER.warning(f'Could not remove previous ipxe debug binary {ipxe_debug_binary}')
                update_active_binaries = True
                ipxe_debug_binary = new_ipxe_debug_binary

            debug_ipxe_timestamp.delete()

        if update_active_binaries:
            update_ipxe_config_binaries(api_instance, ipxe_binary_name, ipxe_debug_binary_name)

        # Settings are now "nominal", with content applied to the artifacts.
        settings_changed = False
        ca_public_key_changed = False
        bss_script_changed = False
        shell_script_changed = False
        bearer_token_changed = False
        time.sleep(30)


if __name__ == '__main__':
    # Format logs and set the requested log level.
    log_format = "%(asctime)-15s - %(levelname)-7s - %(name)s - %(message)s"
    requested_log_level = os.environ.get('LOG_LEVEL', 'INFO')
    log_level = logging.getLevelName(requested_log_level)

    bad_log_level = None
    if type(log_level) != int:
        bad_log_level = requested_log_level
        log_level = logging.INFO

    logging.basicConfig(level=log_level, format=log_format)
    if bad_log_level:
        LOGGER.warning('Log level %r is not valid. Falling back to INFO',
                       bad_log_level)

    LOGGER.info("Cray IPXE builder Initializing...")
    os.chdir(IPXE_BUILD_DIR)
    main()
