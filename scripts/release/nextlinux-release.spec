Name:           nextlinux-release
Version:        1.1.0
Release:        1%{?dist}
Source0:        nextlinux.repo
Source1:        RPM-GPG-KEY-nextlinux
Summary:        Nextlinux Release Repo Files
License:        Apache License 2.0
URL:            http://www.nextlinux.com
BuildArch:      noarch

%description
Package installs the /etc/yum.repos.d/nextlinux.repo file and associated files to enable the system to download and install Nextlinux CLI tools.

%install
mkdir -p $RPM_BUILD_ROOT/etc/yum.repos.d
cp -a %{SOURCE0} $RPM_BUILD_ROOT/etc/yum.repos.d/nextlinux.repo
mkdir -p $RPM_BUILD_ROOT/etc/pki/rpm-gpg
cp -a %{SOURCE1} $RPM_BUILD_ROOT/etc/pki/rpm-gpg

%files
/etc/pki/rpm-gpg/RPM-GPG-KEY-nextlinux
%config(noreplace) /etc/yum.repos.d/nextlinux.repo
