# cray-ipxe

This is the CMS ipxe project; it is a build project used to distribute
Cray purpose built ipxe binaries to booting hardware. It leverages the existing
internal third party ipxe Docker build environment as a starting point, and
then further supplies its own chainload to the BSS service.

## JWT Authentication

An bearer token can be included into the ipxe image built by this project.
The token if configured will be used by ipxe when making all requests and will take
the form of an HTTP Authorization header.  The token is optional and if not
configured ipxe requests will not include the auth header.  Note that redirect
requests will not include the bearer token (an explicit requirement of AWS S3).  

Example 'Authorization: Bearer TOKEN'

To configure add the token to the settings configmap by including a
'cray_ipxe_build_bearer_token' key and value.

Example:
kubectl edit configmap cray-ipxe-settings -n default

```
Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#
apiVersion: v1
data:
 cray_ipxe_build_bearer_token: |
   VALID_JWT_TOKEN_GOES_HERE
 settings.yaml: |
   cray_ipxe_build_x86: True
   cray_ipxe_build_bss: True
   cray_ipxe_build_shell: True
   cray_ipxe_build_with_cert: False
   cray_ipxe_build_debug: True
```

The cms-ipxe service will detect changes to the settings and rebuild the iPXE
binary as required.  The binary is then copied to the tftp location for use at
node boot time.

Note that the console output of the cray-ipxe pod will show explicit messages
including the make command line and the arguments used to build ipxe.  This
is useful to verify expected responses to changes in the configmap values.  The
token used to build ipxe is included as a make argument.

### Authentication request / response debugging

'cray_ipxe_build_debug' is optional.  If true it will enable additional debugging
in the ipxe binary useful for viewing the details of the ipxe requests
and responses from the compute node console.  Configure this as per the example
above.

## Testing

See cms-tools repo for details on running CT tests for this service.

## Versioning
Use [SemVer](http://semver.org/). The version is located in the [.version](.version) file. Other files either
read the version string from this file or have this version string written to them at build time 
based on the information in the [update_versions.conf](update_versions.conf) file (using the 
update_versions.sh script in the cms-meta-tools repo).

## Copyright and License
This project is copyrighted by Hewlett Packard Enterprise Development LP and is under the MIT
license. See the [LICENSE](LICENSE) file for details.

When making any modifications to a file that has a Cray/HPE copyright header, that header
must be updated to include the current year.

When creating any new files in this repo, if they contain source code, they must have
the HPE copyright and license text in their header, unless the file is covered under
someone else's copyright/license (in which case that should be in the header). For this
purpose, source code files include Dockerfiles, Ansible files, RPM spec files, and shell
scripts. It does **not** include Jenkinsfiles, OpenAPI/Swagger specs, or READMEs.

When in doubt, provided the file is not covered under someone else's copyright or license, then
it does not hurt to add ours to the header.
