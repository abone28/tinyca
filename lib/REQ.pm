# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: REQ.pm,v 1.19 2004/05/06 19:22:23 sm Exp $
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.

use strict;

package REQ;

use POSIX;
use Locale::gettext;

sub new {
   my $that = shift;
   my $class = ref($that) || $that;

   my $self = {};

   bless($self, $class);
}

#
# check if all data for creating a new request is available
#
sub get_req_create {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my ($name, $action, $parsed, $reqfile, $keyfile, $ca);

   $ca   = $main->{'CA'}->{'actca'};

   if(!(defined($opts))) {
      $opts->{'bits'}   = 2048;
      $opts->{'digest'} = 'sha1';
      $opts->{'algo'}   = 'rsa';
   
      $parsed = $main->{'CERT'}->parse_cert($main, 'CA');
      
      defined($parsed) || 
         $main->print_error(gettext("Can't read CA certificate"));
   
      # set defaults
      if(defined $parsed->{'C'}) {
         $opts->{'C'} = $parsed->{'C'};
      }
      if(defined $parsed->{'ST'}) {
         $opts->{'ST'} = $parsed->{'ST'};
      }
      if(defined $parsed->{'L'}) {
         $opts->{'L'} = $parsed->{'L'};
      }
      if(defined $parsed->{'O'}) {
         $opts->{'O'} = $parsed->{'O'};
      }
      if(defined $parsed->{'OU'}) {
         $opts->{'OU'} = $parsed->{'OU'}->[0];
      }

      $main->show_req_dialog($opts);
      return;
   }

   if((not defined($opts->{'C'})) ||
      ($opts->{'C'} eq "") ||
      (not defined($opts->{'CN'})) ||
      ($opts->{'CN'} eq "") ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'passwd'} eq "")) {
      $main->show_req_dialog($opts); 
      $main->print_warning(gettext("Please specify at least Common Name, ")
                          .gettext("Country and Password"));
      return;
   }

   if((not defined($opts->{'passwd2'})) ||
       $opts->{'passwd'} ne $opts->{'passwd2'}) { 
      $main->show_req_dialog($opts); 
      $main->print_warning(gettext("Passwords don't match"));
      return;
   }

   $opts->{'C'} = uc($opts->{'C'});

   if(length($opts->{'C'}) != 2) {
      $main->show_req_dialog($opts); 
      $main->print_warning(gettext("Country must be exact 2 letter code"));
      return;
   }

   $name = _gen_name($opts);

   $opts->{'reqname'} = MIME::Base64::encode($name, '');

   $reqfile = $main->{'CA'}->{$ca}->{'dir'}."/req/".$opts->{'reqname'}.".pem";
   $keyfile = $main->{'CA'}->{$ca}->{'dir'}."/keys/".$opts->{'reqname'}.".pem";

   if(-s $reqfile || -s $keyfile) {
      $main->show_req_overwrite_warning($opts);
      return;
   }

   $self->create_req($main, $opts);

   return;
}

#
# create new request and key
#
sub create_req {
   my ($self, $main, $opts) = @_;

   my($reqfile, $keyfile, $ca);

   $ca   = $main->{'CA'}->{'actca'};

   $reqfile = $main->{'CA'}->{$ca}->{'dir'}."/req/".$opts->{'reqname'}.".pem";
   $keyfile = $main->{'CA'}->{$ca}->{'dir'}."/keys/".$opts->{'reqname'}.".pem";
         
   $main->{'OpenSSL'}->newkey(
         'algo'    => $opts->{'algo'},
         'bits'    => $opts->{'bits'},
         'outfile' => $keyfile,
         'pass'    => $opts->{'passwd'}
         );

   if (not -s $keyfile) { 
      unlink($keyfile);
      $main->print_warning(gettext("Generating key failed"));
      return;
   }

   $main->{'OpenSSL'}->newreq(
         'config'   => $main->{'CA'}->{$ca}->{'cnf'},
         'outfile'  => $reqfile,
         'keyfile'  => $keyfile,
         'digest'   => $opts->{'digest'},
         'pass'     => $opts->{'passwd'},
         'dn'       => [ $opts->{'C'},
                         $opts->{'ST'},
                         $opts->{'L'},
                         $opts->{'O'},
                         $opts->{'OU'},
                         $opts->{'CN'},
                         $opts->{'EMAIL'},
                         '',
                         ''
                       ],
         );

   if (not -s $reqfile) { 
      unlink($keyfile);
      unlink($reqfile);
      $main->print_warning(gettext("Generating Request failed"));
      return;
   }

   $main->create_mframe();

   return;
}

#
# get name of requestfile to delete
#
sub get_del_req {
   my ($self, $main) = @_;

   my($reqname, $req, $reqfile, $row, $ind, $ca);

   $ca   = $main->{'CA'}->{'actca'};

   $row = $main->{'reqlist'}->selection(); 
   $ind = $main->{'reqlist'}->get_text($row, 7);

   if(not defined($ind)) {
      $main->print_info(gettext("Please select a Request first"));
      return;
   }

   $req = $self->{'reqlist'}->[$ind];

   $reqname = MIME::Base64::encode($req, '');

   $reqfile = $main->{'CA'}->{$ca}->{'dir'}."/req/".$reqname.".pem";

   if(not -s $reqfile) {
      $main->print_warning(gettext("Request file not found"));
      return;
   }

   $main->show_del_confirm($reqfile, 'req');

   return;
}

#
# now really delete the requestfile
#
sub del_req {
   my ($self, $main, $file) = @_;

   unlink($file);

   $main->create_mframe();

   return;
}

sub read_reqlist {
   my ($self, $main) = @_;

   my ($f, $modt, $d, $ca, $reqdir, $reqlist);

   $ca     = $main->{'CA'}->{'actca'};
   $reqdir = $main->{'CA'}->{$ca}->{'dir'}."/req";

   $reqlist = [];

   $modt = (stat($reqdir))[9];

   if(defined($self->{'lastread'}) &&
      $self->{'lastread'} >= $modt) {  
      return(0);
   }

   opendir(DIR, $reqdir) || do {
      $main->print_warning(gettext("Can't open Request directory"));
      return(0);
   };

   while($f = readdir(DIR)) {
      next if $f =~ /^\./;
      $f =~ s/\.pem//;
      $d = MIME::Base64::decode($f);
      next if not defined($d);
      next if $d eq "";
      push(@{$reqlist}, $d);
   }
   @{$reqlist} = sort(@{$reqlist});
   closedir(DIR);

   $self->{'reqlist'} = $reqlist;

   $self->{'lastread'} = time();
   return(1);  # got new list
}

#
# get name of request to sign
#
sub get_sign_req {
   my ($self, $main, $opts, $box) = @_;

   my($row, $ind, $time, $parsed, $ca);

   $ca   = $main->{'CA'}->{'actca'};

   $box->destroy() if(defined($box));
   
   $time = time();

   if(not(defined($opts->{'reqfile'}))) {
      $row = $main->{'reqlist'}->selection(); 
      $ind = $main->{'reqlist'}->get_text($row, 7);

      if(not defined($ind)) {
         $main->print_info(gettext("Please select a Request first"));
         return;
      }

      $opts->{'req'} = $self->{'reqlist'}->[$ind];

      $opts->{'reqname'} = MIME::Base64::encode($opts->{'req'}, '');

      $opts->{'reqfile'} =
         $main->{'CA'}->{$ca}->{'dir'}."/req/".$opts->{'reqname'}.".pem";

      if(not -s $opts->{'reqfile'}) {
         $main->print_warning(gettext("Request file not found"));
         return;
      }
   }
   
   if((-s $main->{'CA'}->{$ca}->{'dir'}."/certs/".$opts->{'reqname'}.".pem") &&
      (!(defined($opts->{'overwrite'})) || ($opts->{'overwrite'} ne 'true'))) {
      $main->show_cert_overwrite_confirm($opts);
      return;
   }

   if(!defined($opts->{'passwd'})) {
      $opts->{'days'} =
         $main->{'TCONFIG'}->{$opts->{'type'}."_ca"}->{'default_days'};
      $main->show_req_sign_dialog($opts); 
      return; 
   }

   $parsed = $main->{'CERT'}->parse_cert($main, 'CA');

   defined($parsed) || $main->print_error(gettext("Can't read CA certificate"));

   if((($time + ($opts->{'days'} * 86400)) > $parsed->{'EXPDATE'}) &&
      (!(defined($opts->{'ignoredate'})) || $opts->{'ignoredate'} ne 'true')){
      $main->show_req_date_warning($opts);
      return;
   }

   $self->sign_req($main, $opts);
   return;
}

#
# now really sign the request
#
sub sign_req {
   my ($self, $main, $opts) = @_;

   my($serial, $certout, $certfile, $certfile2, $ca, $ret, $t);

   $ca = $main->{'CA'}->{'actca'};

   $serial = $main->{'CA'}->{$ca}->{'dir'}."/serial";
   open(IN, "<$serial") || do {
      $main->print_warning(gettext("Can't read serial"));
      return;
   };
   $serial = <IN>;
   chomp($serial);
   close IN;

   if(not defined($opts->{'nsSslServerName'})) {
      $opts->{'nsSslServerName'} = 'none';
   }
   if(not defined($opts->{'nsRevocationUrl'})) {
      $opts->{'nsRevocationUrl'} = 'none';
   }
   if(not defined($opts->{'nsRenewalUrl'})) {
      $opts->{'nsRenewalUrl'} = 'none';
   }
   if(not defined($opts->{'subjectAltName'})) {
      $opts->{'subjectAltName'}     = 'none';
      $opts->{'subjectAltNameType'} = 'none';
   } else {
       $opts->{'subjectAltNameType'} = 
          $main->{TCONFIG}->{$opts->{'type'}.'_cert'}->{'subjectAltNameType'};
   }

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      $ret = $main->{'OpenSSL'}->signreq(
            'mode'            => $opts->{'mode'},
            'config'          => $main->{'CA'}->{$ca}->{'cnf'},
            'reqfile'         => $opts->{'reqfile'},
            'keyfile'         => $opts->{'keyfile'},
            'cacertfile'      => $opts->{'cacertfile'},
            'outdir'          => $opts->{'outdir'},
            'days'            => $opts->{'days'},
            'parentpw'        => $opts->{'parentpw'},
            'caname'          => "ca_ca",
            'revocationurl'   => $opts->{'nsRevocationUrl'},
            'renewalurl'      => $opts->{'nsRenewalUrl'},
            'subjaltname'     => $opts->{'subjectAltName'},
            'subjaltnametype' => $opts->{'subjectAltNameType'}
            );
   } else {
      $ret = $main->{'OpenSSL'}->signreq(
            'config'          => $main->{'CA'}->{$ca}->{'cnf'},
            'reqfile'         => $opts->{'reqfile'},
            'days'            => $opts->{'days'},
            'pass'            => $opts->{'passwd'},
            'caname'          => $opts->{'type'}."_ca",
            'sslservername'   => $opts->{'nsSslServerName'},
            'revocationurl'   => $opts->{'nsRevocationUrl'},
            'renewalurl'      => $opts->{'nsRenewalUrl'},
            'subjaltname'     => $opts->{'subjectAltName'},
            'subjaltnametype' => $opts->{'subjectAltNameType'}
            );
   }

   if($ret == 1) {
      $t = gettext("Wrong CA password given\nSigning of the Request failed");
      $main->print_warning($t);
      return;
   } elsif($ret == 2) {
      $t = gettext("CA Key not found\nSigning of the Request failed");
      $main->print_warning($t);
      return;
   } elsif($ret == 3) {
      $t = gettext("Certificate already existing\nSigning of the Request failed");
      $main->print_warning($t);
      return;
   } elsif($ret == 4) {
      $t = gettext("Invalid IP Address given\nSigning of the Request failed");
      $main->print_warning($t);
      return;
   } elsif($ret) {
      $main->print_warning(gettext("Signing of the Request failed"));
      return;
   }

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      $certout  = $main->{'CA'}->{$ca}->{'dir'}."/newcerts/".$serial.".pem";
      $certfile = $opts->{'outfile'};
      $certfile2 = $main->{'CA'}->{$ca}->{'dir'}."/certs/".$opts->{'reqname'}.".pem";
   } else {
      $certout  = $main->{'CA'}->{$ca}->{'dir'}."/newcerts/".$serial.".pem";
      $certfile = $main->{'CA'}->{$ca}->{'dir'}."/certs/".$opts->{'reqname'}.".pem";
   }

   if (not -s $certout) {
         $main->print_warning(gettext("Signing of the Request failed"));
         return;
   }

   open(IN, "<$certout") || do {
      $main->print_warning(gettext("Can't read Certificate file"));
      return;
   };
   open(OUT, ">$certfile") || do {
      $main->print_warning(gettext("Can't write Certificate file"));
      return;
   };
   print OUT while(<IN>);

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      close OUT;
      open(OUT, ">$certfile2") || do {
         $main->print_warning(gettext("Can't write Certificate file"));
         return;
      };
      seek(IN, 0, 0);
      print OUT while(<IN>);
   }
   
   close IN; close OUT;

   $main->print_info("Request signed succesfully.\nCertificate created");
   
   # force reread of certlist
   $main->{'CERT'}->read_certlist($main, 1);

   $main->create_mframe();
     
   return;
}

#
# get informations/verifications to import reuest from file
#
sub get_import_req {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my($ca, $parsed, $file, $format);

   $ca = $main->{'CA'}->{'actca'};

   if(not defined($opts)) {
      $main->show_req_import_dialog();
      return;
   }

   if(not defined($opts->{'infile'})) {
      $main->show_req_import_dialog();
      $main->print_warning(gettext("Please select a Request file first"));
      return;
   }
   if(not -s $opts->{'infile'}) {
      $main->show_req_import_dialog();
      $main->print_warning(
            gettext("Can't find Request file: ").$opts->{'infile'});
      return;
   }

   open(IN, "<$opts->{'infile'}") || do {
      $main->print_warning(
            gettext("Can't read Request file:").$opts->{'infile'});
      return;
   };

   $opts->{'in'} .= $_ while(<IN>);

   if($opts->{'in'} =~ /-BEGIN[\s\w]+CERTIFICATE REQUEST-/i) {
      $format = "PEM";
      $file = $opts->{'infile'};
   } else {
      $format = "DER";
   }

   if($format eq "DER") {
      $opts->{'in'} = $main->{'OpenSSL'}->convdata(
            'cmd'     => 'req',
            'main'    => $main,
            'data'    => $opts->{'in'},
            'inform'  => 'DER',
            'outform' => 'PEM'
            );

      $opts->{'tmpfile'} = _mktmp($main->{'OpenSSL'}->{'tmp'}."/import");
   
      open(TMP, ">$opts->{'tmpfile'}") || do {
         $main->print_warning( gettext("Can't create temporary file: %s: %s"),
               $opts->{'tmpfile'}, $!);
         return;
      };
      print TMP $opts->{'in'};
      close(TMP);
      $file = $opts->{'tmpfile'};
   }

   $parsed = $main->{'OpenSSL'}->parsereq($main, $file);
   
   if(not defined($parsed)) {
      unlink($opts->{'tmpfile'});
      $main->print_warning(gettext("Parsing Request failed"));
      return;
   }
   
   $main->show_req_import_verification($opts, $parsed);
   return;
}

#
# import request
#
sub import_req {
   my ($self, $main, $opts, $parsed, $box) = @_;

   $box->destroy() if(defined($box));
   
   my $ca = $main->{'CA'}->{'actca'};

   $opts->{'name'} = _gen_name($parsed);
   
   $opts->{'reqname'} = MIME::Base64::encode($opts->{'name'}, '');

   $opts->{'reqfile'} = 
      $main->{'CA'}->{$ca}->{'dir'}."/req/".$opts->{'reqname'}.".pem";

   open(OUT, ">$opts->{'reqfile'}") || do {
      unlink($opts->{'tmpfile'});
      $main->print_warning(gettext("Can't open output file: %s: %s"),
            $opts->{'reqfile'}, $!);
      return;
   };
   print OUT $opts->{'in'};
   close OUT;

   $main->create_mframe();

   return;
}

sub parse_req {
   my ($self, $main, $name) = @_;
   
   my ($parsed, $ca, $reqfile, $req);

   $ca = $main->{'CA'}->{'actca'};

   $reqfile = $main->{'CA'}->{$ca}->{'dir'}."/req/".$name.".pem";

   $parsed = $main->{'OpenSSL'}->parsereq( $main, $reqfile);

   return($parsed);
}


sub _mktmp {
   my $base = shift;

   my @rand = ();
   my $ret  = '';

   do {
      for(my $i = 0; $i < 8; $i++) { 
         push(@rand, int(rand 26)+65);
      }
      my $end = pack("C8", @rand);
      $ret = $base.$end; 
   } while (-e $ret);

   return($ret);
}

sub _gen_name {
   my $opts = shift;

   my $name = '';

   foreach (qw(CN EMAIL OU O L ST C)) {
      if((not defined($opts->{$_})) || ($opts->{$_} eq '')) {
         $opts->{$_} = ".";
      }
      if($opts->{$_} ne '.' && not ref($opts->{$_})) {
         $name .= $opts->{$_};
      } elsif (ref($opts->{$_})) {
         $name .= $opts->{$_}->[0];
      } else {
         $name .= " ";
      }
      $name .= ":" if($_ ne 'C');
   }

   return($name);
}

1

# 
# $Log: REQ.pm,v $
# Revision 1.19  2004/05/06 19:22:23  sm
# added display and export for DSA and RSA keys
#
# Revision 1.17  2004/05/05 20:59:42  sm
# added configuration for CA
#
# Revision 1.14  2004/05/04 20:34:58  sm
# added patches from Olaf Gellert <og@pre-secure.de> for selecting the Digest
#
# Revision 1.13  2004/05/02 18:39:30  sm
# added possibility to create SubCA
# add new section to config for that
#
# Revision 1.10  2003/10/01 20:48:43  sm
# configure nsRenewalUrl and set during signing
#
# Revision 1.9  2003/10/01 13:57:42  sm
# configure nsRevocationUrl and ask during signing
#
# Revision 1.8  2003/10/01 12:42:48  sm
# configure subjectAltName for client and ask during signing
#
# Revision 1.7  2003/09/29 17:02:39  sm
# configure subjectAltName and set during signing
#
# Revision 1.6  2003/09/02 19:38:43  sm
# change nsSslServerName when signing
#
# Revision 1.5  2003/08/27 20:40:38  sm
# started adding errorhandling
#
# Revision 1.4  2003/08/22 20:36:56  sm
# code cleanup
#
# Revision 1.3  2003/08/16 22:05:24  sm
# first release with Gtk-Perl
#
# Revision 1.2  2003/08/13 19:39:37  sm
# rewrite for Gtk
#
# Revision 1.9  2003/07/04 22:58:58  sm
# first round of the translation is done
#
# Revision 1.8  2003/07/03 20:59:03  sm
# a lot of gettext() inserted
#
# Revision 1.7  2003/06/23 20:11:30  sm
# some new texts from ludwig.nussel@suse.de
#
# Revision 1.6  2003/06/19 21:46:43  sm
# change button status dynamically
#
# Revision 1.4  2002/10/04 09:02:50  sm
# fixed typo
#
# Revision 1.3  2002/10/04 09:01:51  sm
# avoid empty lines in list if decoding of filenames failed
# set days to 365 default
#
# Revision 1.2  2002/09/27 19:51:04  sm
# Fixed typo in _gen_name()
#
# 
