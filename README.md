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

### CT Tests 
CT tests can be found in /ct-tests

On a physical system, CMS tests can be found in /opt/cray/tests/crayctl-stage{NUMBER}/cms
Please see https://connect.us.cray.com/confluence/display/DST/Stage+Tests+Guidelines for more details.

example: run CT test for IPXE at crayctl stage 4
```
# /opt/cray/tests/crayctl-stage4/cms/ipxe_stage4_ct_tests.sh or
# cmsdev test ipxe --ct
```

Tests return 0 for success, 1 otherwise
