%global debug_package %{nil}
%bcond check 1
%global cargo_install_lib 0

%global crate subid_dyn 

Name:           subid-dyn
Version:        0.1.0
Release:        %autorelease
Summary:        NSS and PAM module to dynamic alloc subid ranges.

License:        MIT
URL:            https://github.com/chlorodose/subid_dyn
Source:         %{crate}.crate
Source:         vendor.tar.gz

BuildRequires:  cargo-rpm-macros >= 26
BuildRequires:  pam-devel

%description
NSS and PAM module to dynamic alloc subid ranges.

%files
%license LICENSE
%doc README.md
%{_libdir}/security/pam_ensure_subid.so
%{_libdir}/libsubid_dyn.so

%prep
%autosetup -n %{crate}-%{version} -p1 -a1
%cargo_prep -v vendor

%build
%cargo_build

%install
install -D target/rpm/libsubid_dyn.so %{buildroot}%{_libdir}/libsubid_dyn.so
install -d %{buildroot}%{_libdir}/security/
ln -sf ../libsubid_dyn.so %{buildroot}%{_libdir}/security/pam_ensure_subid.so

%if %{with check}
%check
%cargo_test
%endif

%changelog
%autochangelog
