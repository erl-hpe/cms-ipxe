# Copyright 2019 Cray Inc. All Rights Reserved.

Name: cray-ipxe-crayctldeploy
License: Cray Software License Agreement
Summary: Cray iPXE service
Group: System/Management
Version: %(cat .rpm_version)
Release: %(echo ${BUILD_METADATA})
Source: %{name}-%{version}.tar.bz2
Vendor: Cray Inc.
Requires: cray-crayctl
Requires: cray-cmstools-crayctldeploy
Requires: kubernetes-crayctldeploy

# Project level defines TODO: These should be defined in a central location; DST-892
%define afd /opt/cray/crayctl/ansible_framework

%description
This is a collection of resources for cms-ipxe

%prep
%setup -q

%build

%install

# Install smoke tests under /opt/cray/tests/crayctl-stage4
mkdir -p ${RPM_BUILD_ROOT}/opt/cray/tests/crayctl-stage4/cms/
cp ct-tests/ipxe_stage4_ct_tests.sh ${RPM_BUILD_ROOT}/opt/cray/tests/crayctl-stage4/cms/ipxe_stage4_ct_tests.sh

%clean

%files
%defattr(755, root, root)

/opt/cray/tests/crayctl-stage4/cms/ipxe_stage4_ct_tests.sh

%changelog
