# spec file for package tinyca
#
# $Id: tinyca.spec,v 1.14 2004/07/08 16:13:09 sm Exp $
#
# Copyright (c) 2002 Stephan Martin
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

# neededforbuild  update-desktop-files
# usedforbuild    aaa_base acl attr bash bind-utils bison bzip2 coreutils cpio cpp cracklib cvs cyrus-sasl db devs diffutils e2fsprogs file filesystem fillup findutils flex gawk gdbm-devel glibc glibc-devel glibc-locale gpm grep groff gzip info insserv kbd less libacl libattr libgcc libselinux libstdc++ libxcrypt m4 make man mktemp module-init-tools ncurses ncurses-devel net-tools netcfg openldap2-client openssl pam pam-modules patch permissions popt procps pwdutils rcs readline sed sendmail strace syslogd sysvinit tar texinfo timezone unzip util-linux vim zlib zlib-devel autoconf automake binutils gcc gdbm gettext libtool perl rpm update-desktop-files 

%define	bindir		%{_bindir}
%define	libdir		%{_datadir}/TinyCA/lib
%define	templatesdir	%{_datadir}/TinyCA/templates
%define	localedir	%{_datadir}/TinyCA/locale/

Name:       tinyca
URL:        http://tinyca.sm-zone.net/
Group:      Productivity/Networking/Security
License:	   GPL
Requires:	perl perl-Gtk-Perl perl-MIME-Base64
Packager:	Stephan Martin <sm@sm-zone.net>
Version:    @version@
Release:    0
Source0:    %{name}-%{version}.tar.gz
Source1:    %{name}.desktop
Summary:	   Graphical Tool for Managing a Certification Authority
BuildArch:  noarch
BuildRoot:  %{_tmppath}/%{name}-%{version}-build

%description 
TinyCA is a graphical tool written in Perl/Gtk to manage a small
Certification Authority (CA) using openssl.

TinyCA supports - creation and revocation of x509 - S/MIME
   certificates.

- PKCS#10 requests.

- exporting certificates as PEM, DER, TXT, and PKCS#12.

- server certificates for use in web servers, email servers, IPsec,
   and more.

- client certificates for use in web browsers, email clients, IPsec,
  and more.

- creation and management of SubCAs


Authors:
--------
Stephan Martin <sm@sm-zone.net>

%prep
%setup

%build
# Configure pristine source
perl -pi -e 's:./lib:%{libdir}:g' tinyca
perl -pi -e 's:./templates:%{templatesdir}:g' tinyca
perl -pi -e 's:./locale:%{localedir}:g' tinyca
make -C po

%install
[ "$RPM_BUILD_ROOT" != "/" ] && [ -d $RPM_BUILD_ROOT ] && rm -rf $RPM_BUILD_ROOT;

mkdir -p $RPM_BUILD_ROOT%{bindir}
mkdir -p $RPM_BUILD_ROOT%{libdir}
mkdir -p $RPM_BUILD_ROOT%{libdir}/GUI
mkdir -p $RPM_BUILD_ROOT%{templatesdir}
mkdir -p $RPM_BUILD_ROOT%{localedir}/de/LC_MESSAGES/
install -m 644 lib/*.pm $RPM_BUILD_ROOT%{libdir}
install -m 644 lib/GUI/*.pm $RPM_BUILD_ROOT%{libdir}/GUI/
install -m 644 templates/openssl.cnf $RPM_BUILD_ROOT%{templatesdir}
install -m 755 tinyca $RPM_BUILD_ROOT%{bindir}
install -m 644 locale/de/LC_MESSAGES/tinyca.mo %{buildroot}%{localedir}/de/LC_MESSAGES/

%if %suse_version > 820
%suse_update_desktop_file -i %name Network Security
%endif

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc CHANGES
%dir %{_datadir}/TinyCA
%{bindir}/tinyca
%{_datadir}/TinyCA/*
%if %suse_version > 820
%{_datadir}/applications/*
%endif

%changelog
* Sun Jun 13 2004 - sm@sm-zone.net
- gui polishing
- code cleanup
- some usability improvements
* Wed Jun  2 2004 - sm@sm-zone.net
- gui polishing
- GUI module splitted to several files
* Fri Oct  3 2003 - sm@sm-zone.net
- added a lot of configuration options
- correctly import/show details of requests without extensions
  (thanks to James.Leavitt@anywaregroup.com)
* Mon Sep  1 2003 - sm@sm-zone.net
- added renewal of certificates
* Wed Aug 13 2003 - sm@sm-zone.net
- rewite, now using perl-Gtk
* Sat Jul  5 2003 - sm@sm-zone.net
- added german translation
* Tue Jul  1 2003 - sm@sm-zone.net
- convert index.txt if openssl changed from 0.9.6x to 0.9.7x
* Fri Jun 27 2003 - sm@sm-zone.net
- added export into zip-file
  thanks to ludwig.nussel@suse.de
* Mon Jun 23 2003 - sm@sm-zone.net
- some tiny usability improvements
  thanks to ludwig.nussel@suse.de again
* Thu Jun 19 2003 - sm@sm-zone.net
- some usability improvements
  thanks to ludwig.nussel@suse.de
- some more configuration options
* Fri Oct  4 2002 - sm@sm-zone.net
- Fixed bug exporting keys in PEM format
- Fixed possible empty lines in cert/key/reqlist
  thanks to waldemar.mertke@gmx.de
* Fri Sep 27 2002 - sm@sm-zone.net
- fixed some minor bugs and typos (e.g. concerning openssl 0.9.7)
  thanks to iebgener@yahoo.com and waldemar.mertke@gmx.de
* Wed Aug 21 2002 - sm@sm-zone.net
- fixed revocation
- added some colors
- thanks to curly@e-card.bg
* Sun Aug 18 2002 - sm@sm-zone.net
- new version 0.4.0
- works independent of OpenCA modules now
- some enhancements to functionality (e.g. export of key without
  passwd)
- some smaller bugfixes in usability
- new specfile (thanks to oron@actcom.co.il)
* Thu Jun  6 2002 - Oron Peled <oron@actcom.co.il>
- Cleaned .spec file
* Mon Jun  3 2002 - sm@sm-zone.net
- fixed wrong templatedir when creating new CA
* Sun Jun  2 2002 - sm@sm-zone.net
- fixed some minor bugs and typos
* Sat May 11 2002 - sm@sm-zone.net
- Added parser for x509 extensions
* Fri May 03 2002 - sm@sm-zone.net
- added possibility to view requests/certificates
* Thu Apr 18 2002 - sm@sm-zone.net
- added configuration
* Sun Apr  7 2002 - sm@sm-zone.net
- improved usability
* Sun Mar 31 2002 - sm@sm-zone.net
- added function to delete ca
* Sat Mar 30 2002 - sm@sm-zone.net
- allow import of pkcs#10 requests
* Thu Mar 21 2002 - sm@sm-zone.et
- use different listboxes
* Mon Mar 18 2002 - sm@sm-zone.net
- initial package

