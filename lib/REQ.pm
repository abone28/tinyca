# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: REQ.pm,v 1.46 2005/02/13 21:04:07 sm Exp $
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

   $self->{'OpenSSL'} = shift;

   bless($self, $class);
}

#
# check if all data for creating a new request is available
#
sub get_req_create {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my ($name, $action, $parsed, $reqfile, $keyfile, $ca, $t);

   $ca   = $main->{'CA'}->{'actca'};

   if(!(defined($opts)) || !(ref($opts))) {
      if(defined($opts) && $opts eq "signserver") {
         $opts = {};
         $opts->{'sign'} = 1;
         $opts->{'type'} = "server";
      } elsif(defined($opts) && $opts eq "signclient") {
         $opts = {};
         $opts->{'sign'} = 1;
         $opts->{'type'} = "client";
      } elsif (defined($opts)) {
         $t = sprintf(gettext("Strange value for 'opts': %s"), $opts);
         GUI::HELPERS::print_error($t);
      }
      $opts->{'bits'}   = 4096;
      $opts->{'digest'} = 'sha1';
      $opts->{'algo'}   = 'rsa';
      if(defined($opts) && $opts eq "sign") {
         $opts->{'sign'} = 1;
      }
   
      $parsed = $main->{'CERT'}->parse_cert($main, 'CA');
      
      defined($parsed) || 
         GUI::HELPERS::print_error(gettext("Can't read CA certificate"));
   
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
      my $cc = 0;
      foreach my $ou (@{$parsed->{'OU'}}) {
         $opts->{'OU'}->[$cc++] = $ou;
      }

      $main->show_req_dialog($opts);
      return;
   }

   if((not defined($opts->{'CN'})) ||
      ($opts->{'CN'} eq "") ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'passwd'} eq "")) {
      $main->show_req_dialog($opts); 
      GUI::HELPERS::print_warning(
            gettext("Please specify at least Common Name ")
            .gettext("and Password"));
      return;
   }

   if((not defined($opts->{'passwd2'})) ||
       $opts->{'passwd'} ne $opts->{'passwd2'}) { 
      $main->show_req_dialog($opts); 
      GUI::HELPERS::print_warning(gettext("Passwords don't match"));
      return;
   }

   $opts->{'C'} = uc($opts->{'C'});

   if((defined $opts->{'C'}) &&
      ($opts->{'C'} ne "") &&
      (length($opts->{'C'}) != 2)) {
      $main->show_req_dialog($opts); 
      GUI::HELPERS::print_warning(gettext("Country must be exact 2 letter code"));
      return;
   }

   $name = HELPERS::gen_name($opts);

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

   my($reqfile, $keyfile, $ca, $ret, $ext, $cadir);

   GUI::HELPERS::set_cursor($main, 1);
   
   $ca    = $main->{'CA'}->{'actca'};
   $cadir = $main->{'CA'}->{$ca}->{'dir'};

   $reqfile = $cadir."/req/".$opts->{'reqname'}.".pem";
   $keyfile = $cadir."/keys/".$opts->{'reqname'}.".pem";
         
   ($ret, $ext) = $self->{'OpenSSL'}->newkey(
         'algo'    => $opts->{'algo'},
         'bits'    => $opts->{'bits'},
         'outfile' => $keyfile,
         'pass'    => $opts->{'passwd'}
         );

   if (not -s $keyfile || $ret) { 
      unlink($keyfile);
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(gettext("Generating key failed"), $ext);
      return;
   }

   my @dn = ( $opts->{'C'}, $opts->{'ST'}, $opts->{'L'}, $opts->{'O'} );
   if(ref($opts->{'OU'})) {
      foreach my $ou (@{$opts->{'OU'}}) {
      	push(@dn,$ou);
      }
   } else {
      push(@dn, $opts->{'OU'});
   }
   @dn = (@dn, $opts->{'CN'}, $opts->{'EMAIL'}, '', '');
   ($ret, $ext) = $self->{'OpenSSL'}->newreq(
         'config'   => $main->{'CA'}->{$ca}->{'cnf'},
         'outfile'  => $reqfile,
         'keyfile'  => $keyfile,
         'digest'   => $opts->{'digest'},
         'pass'     => $opts->{'passwd'},
         'dn'       => \@dn,
         );

   if (not -s $reqfile || $ret) { 
      unlink($keyfile);
      unlink($reqfile);
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(gettext("Generating Request failed"), $ext);
      return;
   }

   my $parsed = $self->parse_req($main, $opts->{'reqname'}, 1);
   # print STDERR "DEBUG: returned from parse_req: $parsed->{'KEYSIZE'}\n";

   $main->{'reqbrowser'}->update($cadir."/req",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0); 

   $main->update_keys();

   GUI::HELPERS::set_cursor($main, 0);

   if($opts->{'sign'}) {
      $opts->{'reqfile'} = $reqfile;
      $opts->{'passwd'}  = undef; # to sign request, ca-password is needed
      $self->get_sign_req($main, $opts);
   }

   return;
}

#
# get name of requestfile to delete
#
sub get_del_req {
   my ($self, $main) = @_;

   my($reqname, $req, $reqfile, $row, $ind, $ca, $cadir);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   if(not(defined($reqfile))) {
      $req = $main->{'reqbrowser'}->selection_dn(); 


      if(not defined($req)) {
         GUI::HELPERS::print_info(gettext("Please select a Request first"));
         return;
      }

      $reqname = MIME::Base64::encode($req, '');
      $reqfile = $cadir."/req/".$reqname.".pem";

   }

   if(not -s $reqfile) {
      GUI::HELPERS::print_warning(gettext("Request file not found"));
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

   my ($ca, $cadir);

   GUI::HELPERS::set_cursor($main, 1);

   unlink($file);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   $main->{'reqbrowser'}->update($cadir."/req",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0); 

   GUI::HELPERS::set_cursor($main, 0);

   return;
}

sub read_reqlist {
   my ($self, $reqdir, $crlfile, $indexfile, $force, $main) = @_;

   my ($f, $modt, $d, $reqlist, $c, $p, $t);

   GUI::HELPERS::set_cursor($main, 1);

   $reqlist = [];

   $modt = (stat($reqdir))[9];

   if(defined($self->{'lastread'}) &&
      $self->{'lastread'} >= $modt) {  
      GUI::HELPERS::set_cursor($main, 0);
      return(0);
   }

   opendir(DIR, $reqdir) || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(gettext("Can't open Request directory"));
      return(0);
   };

   while($f = readdir(DIR)) { 
      next if $f =~ /^\./;
      $c++;
   }
   rewinddir(DIR);

   while($f = readdir(DIR)) {
      next if $f =~ /^\./;
      $f =~ s/\.pem//;
      $d = MIME::Base64::decode($f);
      next if not defined($d);
      next if $d eq "";
      push(@{$reqlist}, $d);

      if(defined($main)) {
         $t = sprintf(gettext("   Read Request: %s"), $d);
         $main->{'bar'}->set_status($t);
         $p += 100/$c;
         $main->{'bar'}->set_progress($p/100);
         while(Gtk->events_pending) {
            Gtk->main_iteration;
         }
         select(undef, undef, undef, 0.025);
      }
   }
   @{$reqlist} = sort(@{$reqlist});
   closedir(DIR);

   delete($self->{'reqlist'});
   $self->{'reqlist'} = $reqlist;

   $self->{'lastread'} = time();

   if(defined($main)) {
      $main->{'bar'}->set_progress(0);
   }

   GUI::HELPERS::set_cursor($main, 0);

   return(1);  # got new list
}

#
# get name of request to sign
#
sub get_sign_req {
   my ($self, $main, $opts, $box) = @_;

   my($time, $parsed, $ca, $cadir, $ext, $ret);

   $box->destroy() if(defined($box));
   
   $time = time();
   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   if(not(defined($opts->{'reqfile'}))) {
      $opts->{'req'} = $main->{'reqbrowser'}->selection_dn(); 

      if(not defined($opts->{'req'})) {
         GUI::HELPERS::print_info(gettext("Please select a Request first"));
         return;
      }

      $opts->{'reqname'} = MIME::Base64::encode($opts->{'req'}, '');
      $opts->{'reqfile'} = $cadir."/req/".$opts->{'reqname'}.".pem";
   }

   if(not -s $opts->{'reqfile'}) {
         GUI::HELPERS::print_warning(gettext("Request file not found"));
         return;
      }
   
   if((-s $cadir."/certs/".$opts->{'reqname'}.".pem") &&
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

   defined($parsed) || 
      GUI::HELPERS::print_error(gettext("Can't read CA certificate"));

   if((($time + ($opts->{'days'} * 86400)) > $parsed->{'EXPDATE'}) &&
      (!(defined($opts->{'ignoredate'})) || 
       $opts->{'ignoredate'} ne 'true')){
      $main->show_req_date_warning($opts);
      return;
   }

   ($ret, $ext) = $self->sign_req($main, $opts);

   return($ret, $ext);
}

#
# now really sign the request
#
sub sign_req {
   my ($self, $main, $opts) = @_;

   my($serial, $certout, $certfile, $certfile2, $ca, $cadir, $ret, $t, $ext);

   GUI::HELPERS::set_cursor($main, 1);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   $serial = $cadir."/serial";
   open(IN, "<$serial") || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(gettext("Can't read serial"));
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
   if(not defined($opts->{'extendedKeyUsage'})) {
      $opts->{'extendedKeyUsage'}     = 'none';
      $opts->{'extendedKeyUsageType'} = 'none';
   } else {
      $opts->{'extendedKeyUsageType'} = 
         $main->{TCONFIG}->{$opts->{'type'}.'_cert'}->{'extendedKeyUsageType'};
   }

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      ($ret, $ext) = $self->{'OpenSSL'}->signreq(
            'mode'                 => $opts->{'mode'},
            'config'               => $main->{'CA'}->{$ca}->{'cnf'},
            'reqfile'              => $opts->{'reqfile'},
            'keyfile'              => $opts->{'keyfile'},
            'cacertfile'           => $opts->{'cacertfile'},
            'outdir'               => $opts->{'outdir'},
            'days'                 => $opts->{'days'},
            'parentpw'             => $opts->{'parentpw'},
            'caname'               => "ca_ca",
            'revocationurl'        => $opts->{'nsRevocationUrl'},
            'renewalurl'           => $opts->{'nsRenewalUrl'},
            'subjaltname'          => $opts->{'subjectAltName'},
            'subjaltnametype'      => $opts->{'subjectAltNameType'},
            'extendedkeyusage'     => $opts->{'extendedKeyUsage'},
            'extendedkeyusagetype' => $opts->{'extendedKeyUsageType'},
            'noemaildn'            => $opts->{'noemaildn'}
            );
   } else {
      ($ret, $ext) = $self->{'OpenSSL'}->signreq(
            'config'               => $main->{'CA'}->{$ca}->{'cnf'},
            'reqfile'              => $opts->{'reqfile'},
            'days'                 => $opts->{'days'},
            'pass'                 => $opts->{'passwd'},
            'caname'               => $opts->{'type'}."_ca",
            'sslservername'        => $opts->{'nsSslServerName'},
            'revocationurl'        => $opts->{'nsRevocationUrl'},
            'renewalurl'           => $opts->{'nsRenewalUrl'},
            'subjaltname'          => $opts->{'subjectAltName'},
            'subjaltnametype'      => $opts->{'subjectAltNameType'},
            'extendedkeyusage'     => $opts->{'extendedKeyUsage'},
            'extendedkeyusagetype' => $opts->{'extendedKeyUsageType'},
            'noemaildn'            => $opts->{'noemaildn'}
            );

   }

   GUI::HELPERS::set_cursor($main, 0);

   if($ret eq 1) {
      $t = gettext("Wrong CA password given\nSigning of the Request failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 2) {
      $t = gettext("CA Key not found\nSigning of the Request failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 3) {
      $t = gettext("Certificate already existing\nSigning of the Request failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 4) {
      $t = gettext("Invalid IP Address given\nSigning of the Request failed");
      GUI::HELPERS::print_warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret) {
      GUI::HELPERS::print_warning(
            gettext("Signing of the Request failed"), $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return($ret, $ext);
   }

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      $certout  = $cadir."/newcerts/".$serial.".pem";
      $certfile = $opts->{'outfile'};
      $certfile2 = $cadir."/certs/".$opts->{'reqname'}.".pem";
   } else {
      $certout  = $cadir."/newcerts/".$serial.".pem";
      $certfile = $cadir."/certs/".$opts->{'reqname'}.".pem";
      #print STDERR "DEBUG: write certificate to: ".$cadir."/certs/".$opts->{'reqname'}.".pem";
   }

   if (not -s $certout) {
         GUI::HELPERS::print_warning(
               gettext("Signing of the Request failed"), $ext);
         delete($opts->{$_}) foreach(keys(%$opts));
         $opts = undef;
         return;
   }

   open(IN, "<$certout") || do {
      GUI::HELPERS::print_warning(gettext("Can't read Certificate file"));
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   };
   open(OUT, ">$certfile") || do {
      GUI::HELPERS::print_warning(gettext("Can't write Certificate file"));
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   };
   print OUT while(<IN>);

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      close OUT;
      open(OUT, ">$certfile2") || do {
         GUI::HELPERS::print_warning(gettext("Can't write Certificate file"));
         delete($opts->{$_}) foreach(keys(%$opts));
         $opts = undef;
         return;
      };
      seek(IN, 0, 0);
      print OUT while(<IN>);
   }
   
   close IN; close OUT;

   GUI::HELPERS::print_info(
         gettext("Request signed succesfully.\nCertificate created"), $ext);
   
   GUI::HELPERS::set_cursor($main, 1);

   $main->{'CERT'}->reread_cert($main, 
         MIME::Base64::decode($opts->{'reqname'}));
   
   $main->{'certbrowser'}->update($cadir."/certs",
                                  $cadir."/crl/crl.pem",
                                  $cadir."/index.txt",
                                  0);

   delete($opts->{$_}) foreach(keys(%$opts));
   $opts = undef;

   GUI::HELPERS::set_cursor($main, 0);
     
   return($ret, $ext);
}

#
# get informations/verifications to import request from file
#
sub get_import_req {
   my ($self, $main, $opts, $box) = @_;

   my ($ret, $ext, $der);

   $box->destroy() if(defined($box));

   my($ca, $parsed, $file, $format);

   $ca = $main->{'CA'}->{'actca'};

   if(not defined($opts)) {
      $main->show_req_import_dialog();
      return;
   }

   if(not defined($opts->{'infile'})) {
      $main->show_req_import_dialog();
      GUI::HELPERS::print_warning(gettext("Please select a Request file first"));
      return;
   }
   if(not -s $opts->{'infile'}) {
      $main->show_req_import_dialog();
      GUI::HELPERS::print_warning(
            gettext("Can't find Request file: ").$opts->{'infile'});
      return;
   }

   open(IN, "<$opts->{'infile'}") || do {
      GUI::HELPERS::print_warning(
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
      ($ret, $der, $ext) = $opts->{'in'} = $self->{'OpenSSL'}->convdata(
            'cmd'     => 'req',
            'data'    => $opts->{'in'},
            'inform'  => 'DER',
            'outform' => 'PEM'
            );

      if($ret) {
         GUI::HELPERS::print_warning(
               gettext("Error converting Request"), $ext);
         return;
      }

      $opts->{'tmpfile'} = 
         HELPERS::mktmp($self->{'OpenSSL'}->{'tmp'}."/import");
   
      open(TMP, ">$opts->{'tmpfile'}") || do {
         GUI::HELPERS::print_warning( gettext("Can't create temporary file: %s: %s"),
               $opts->{'tmpfile'}, $!);
         return;
      };
      print TMP $opts->{'in'};
      close(TMP);
      $file = $opts->{'tmpfile'};
   }

   $parsed = $self->{'OpenSSL'}->parsereq(
			$main->{'CA'}->{$ca}->{'cnf'},
			$file);
   
   if(not defined($parsed)) {
      unlink($opts->{'tmpfile'});
      GUI::HELPERS::print_warning(gettext("Parsing Request failed"));
      return;
   }
   
   $main->show_import_verification("req", $opts, $parsed);
   return;
}

#
# import request
#
sub import_req {
   my ($self, $main, $opts, $parsed, $box) = @_;

   my ($ca, $cadir);

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);
   
   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   $opts->{'name'} = HELPERS::gen_name($parsed);
   
   $opts->{'reqname'} = MIME::Base64::encode($opts->{'name'}, '');

   $opts->{'reqfile'} = $cadir."/req/".$opts->{'reqname'}.".pem";

   open(OUT, ">$opts->{'reqfile'}") || do {
      unlink($opts->{'tmpfile'});
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(gettext("Can't open output file: %s: %s"),
            $opts->{'reqfile'}, $!);
      return;
   };
   print OUT $opts->{'in'};
   close OUT;

   $main->{'reqbrowser'}->update($cadir."/req",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0);

   GUI::HELPERS::set_cursor($main, 0);

   return;
}

sub parse_req {
   my ($self, $main, $name, $force) = @_;
   
   my ($parsed, $ca, $reqfile, $req);

   GUI::HELPERS::set_cursor($main, 1);

   $ca = $main->{'CA'}->{'actca'};

   $reqfile = $main->{'CA'}->{$ca}->{'dir'}."/req/".$name.".pem";

   $parsed = $self->{'OpenSSL'}->parsereq($main->{'CA'}->{$ca}->{'cnf'},
         $reqfile, $force);

   GUI::HELPERS::set_cursor($main, 0);

   return($parsed);
}

1

# 
# $Log: REQ.pm,v $
# Revision 1.46  2005/02/13 21:04:07  sm
# added multiple ou patch from arndt@uni-koblenz.de
# removed CrlDistributionPoint for Root-CA
# added detection for openssl 0.9.8
#
# Revision 1.45  2004/10/03 08:08:28  sm
# added import verification for ca certificate
#
# Revision 1.44  2004/07/26 09:54:28  sm
# don't crash when deleting last request list
#
# Revision 1.43  2004/07/23 17:44:00  sm
# force reread of request when overwriting an old one
# removed the direct usage of 'OpenSSL.pm' in X509_browser, use correct
# abstraction via 'REQ.pm' and 'CERT.pm'
#
# Revision 1.42  2004/07/23 10:46:14  sm
# reparse request after creation
# delete all internal structures, when opening new ca
#
# Revision 1.41  2004/07/19 14:10:15  sm
# fixed bug (again) signing more request in a row
#
# Revision 1.40  2004/07/15 10:45:47  sm
# removed references to create_mframe, always recreate only one list
#
# Revision 1.39  2004/07/09 10:00:08  sm
# added configuration for extendedKyUsage
#
# Revision 1.38  2004/07/08 10:19:08  sm
# added busy mouse-pointer
# use correct configuration when renewing certificate
#
# Revision 1.37  2004/07/05 20:30:55  sm
# fixed bug, when creating to request directly after creating a new ca
#
# Revision 1.36  2004/07/02 07:34:47  sm
# set default bits to 4096
#
# Revision 1.35  2004/06/23 16:48:24  sm
# added statusbar
# faster reread of reqlist
#
# Revision 1.34  2004/06/17 10:01:07  sm
# use CERT/REQ for lists
#
# Revision 1.31  2004/06/16 13:43:22  sm
# added noemailDN
#
# Revision 1.30  2004/06/15 13:15:56  arasca
# Browsing of certificates and requests moved to new class X509_browser.
#
# Revision 1.29  2004/06/15 12:19:33  sm
# fixed bug creating new requests
#
# Revision 1.28  2004/06/13 13:19:08  sm
# added possibility to generate request and certificate in one step
#
# Revision 1.27  2004/06/06 16:03:56  arasca
# moved infobox (display of cert and req information at bottom of
# tinyca GUI) into extra class.
#
# Revision 1.26  2004/05/27 17:06:57  arasca
# Removed remaining references to $main in OpenSSL.pm
#
# Revision 1.25  2004/05/26 10:28:32  sm
# added extended errormessages to every call of openssl
#
# Revision 1.24  2004/05/26 07:48:36  sm
# adapted functions once more :-)
#
# Revision 1.23  2004/05/26 07:25:47  sm
# moved print_* to GUI::HELPERS.pm
#
# Revision 1.22  2004/05/26 07:03:40  arasca
# Moved miscellaneous functions to new module HELPERS.pm, removed
# Messages.pm and adapted the remaining modules accordingly.
#
# Revision 1.21  2004/05/25 14:44:42  sm
# added textfield to warning dialog
#
# Revision 1.20  2004/05/24 16:05:00  sm
# some more helpers
#
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
