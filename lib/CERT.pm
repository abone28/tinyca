# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: CERT.pm,v 1.15 2004/05/11 18:33:58 sm Exp $
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

package CERT;

use POSIX;
use Locale::gettext;

sub new {
   my $that = shift;
   my $class = ref($that) || $that;

   my $self = {};

   bless($self, $class);
}

#
# read certificates in directory into list
#
sub read_certlist {
   my ($self, $main, $force) = @_;

   my $ca      = $main->{'CA'}->{'actca'};
   my $certdir = $main->{'CA'}->{$ca}->{'dir'}."/certs";
   my $crlfile = $main->{'CA'}->{$ca}->{'dir'}."/crl/crl.pem";

   my($f, $certlist, $crl, $modt, $parsed, $tmp);

   $certlist = [];
   
   $modt = (stat($certdir))[9];

   if(defined($self->{'lastread'}) &&
      ($self->{'lastread'} >= $modt) && 
      not defined($force)) {
      return(0);
   }

   $crl = $main->{'OpenSSL'}->parsecrl($main, $crlfile, $force);

   opendir(DIR, $certdir) || do {
      $main->print_warning(gettext("Can't open certdir"));
      return(0);
   };

   while($f = readdir(DIR)) {
      next if $f =~ /^\./;

      $f =~ s/\.pem//;
      
      $tmp = MIME::Base64::decode($f);
      next if not defined($tmp);
      next if $tmp eq "";

      $parsed = $self->parse_cert( $main, $f, $force);

      defined($parsed) || $main->print_error(gettext("Can't read certificate"));

      $tmp .= "%".$parsed->{'STATUS'};

      push(@{$certlist}, $tmp);
   }
   @{$certlist} = sort(@{$certlist});
   closedir(DIR);

   $self->{'certlist'} = $certlist;

   $self->{'lastread'} = time();

   return(1);  # got new list
}

#
# get information for renewing a certifikate
# 
sub get_renew_cert {
   my ($self, $main, $opts, $box) = @_;

   my ($row, $ind, $cert, $status, $t, $ca);

   $box->destroy() if(defined($box));

   $ca  = $main->{'CA'}->{'actca'};

   if((not defined($opts->{'certfile'})) ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'certfile'} eq '') ||
      ($opts->{'passwd'} eq '')) {
      $row = $main->{'certlist'}->selection();
      $ind = $main->{'certlist'}->get_text($row, 8);
   
      if(not defined($ind)) {
         $main->print_info(gettext("Please select a Certificate first"));
         return;
      }
   
      ($cert, $status) = split(/\%/, $self->{'certlist'}->[$ind]);
   
      if($status eq gettext("VALID")) {
         $t = sprintf(
               gettext("Can't renew Certifikate with Status: %s\nPlease revoke the Certificate first"), 
               $status);
         $main->print_warning($t);
         return;
      } 

      $opts->{'type'} = 'server';
   
      $opts->{'certname'} = MIME::Base64::encode($cert, '');
      $opts->{'reqname'} = $opts->{'certname'};
      $opts->{'certfile'} = 
         $main->{'CA'}->{$ca}->{'dir'}."/certs/".$opts->{'certname'}.".pem";
      $opts->{'keyfile'}  = 
         $main->{'CA'}->{$ca}->{'dir'}."/keys/".$opts->{'certname'}.".pem";
      $opts->{'reqfile'}  = 
         $main->{'CA'}->{$ca}->{'dir'}."/req/".$opts->{'certname'}.".pem";

      if((not -s $opts->{'certfile'}) ||
         (not -s $opts->{'keyfile'})  ||
         (not -s $opts->{'reqfile'})) {
         $t = gettext("Key and Request are necessary for renewal of a Certificate\nRenewal is not possible!");
         $main->print_warning($t);
         return;
      }
   
      $main->show_cert_renew_dialog($opts);
      return;
   }

   $main->{'REQ'}->sign_req($main, $opts);
   
   return;
}

#
# get information for revoking a certifikate
# 
sub get_revoke_cert {
   my ($self, $main, $opts, $box) = @_;

   my ($row, $ind, $cert, $status, $t, $ca);

   $box->destroy() if(defined($box));

   $ca  = $main->{'CA'}->{'actca'};

   if((not defined($opts->{'certfile'})) ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'certfile'} eq '') ||
      ($opts->{'passwd'} eq '')) {
      $row = $main->{'certlist'}->selection();
      $ind = $main->{'certlist'}->get_text($row, 8);
   
      if(not defined($ind)) {
         $main->print_info(gettext("Please select a Certificate first"));
         return;
      }
   
      ($cert, $status) = split(/\%/, $self->{'certlist'}->[$ind]);
   
      if($status ne gettext("VALID")) {
         $t = sprintf(gettext("Can't revoke Certifikate with Status: %s"), 
               $status);
         $main->print_warning($t);
         return;
      }
   
      $opts->{'certname'} = MIME::Base64::encode($cert, '');
      $opts->{'certfile'} = 
         $main->{'CA'}->{$ca}->{'dir'}."/certs/".$opts->{'certname'}.".pem";
   
      $main->show_cert_revoke_dialog($opts);
      return;
   }

   $self->revoke_cert($main, $opts);
   
   return;
}

#
# now really revoke the certificate
#
sub revoke_cert {
   my ($self, $main, $opts) = @_;

   my($ca, $ret, $t);

   $ca  = $main->{'CA'}->{'actca'};

   $ret = $main->{'OpenSSL'}->revoke(
         'config' => $main->{'CA'}->{$ca}->{'cnf'},
         'infile' => 
            $main->{'CA'}->{$ca}->{'dir'}."/certs/".$opts->{'certname'}.".pem",
         'pass'   => $opts->{'passwd'}
         );

   if($ret == 1) {
      $t = gettext("Wrong CA password given\nRevoking the Certificate failed");
      $main->print_warning($t);
      return;
   } elsif($ret == 2) {
      $t = gettext("CA Key not found\nRevoking the Certificate failed");
      $main->print_warning($t);
      return;
   } elsif($ret) {
      $main->print_warning(gettext("Revoking the Certificate failed"));
      return;
   }

   $main->{'OpenSSL'}->newcrl(
         $main,
         'config'  => $main->{'CA'}->{$ca}->{'cnf'},
         'pass'    => $opts->{'passwd'},
         'crldays' => 365,
         'outfile' => $main->{'CA'}->{$ca}->{'dir'}."/crl/crl.pem"
         );

   if (not -s $main->{'CA'}->{$ca}->{'dir'}."/crl/crl.pem") { 
      $main->print_error(gettext("Generating  a new Revocation List failed"));
   }

   # force reread of certlist
   $self->read_certlist($main, 1);

   $main->create_mframe();

   return;
}

#
# get name of certificatefile to delete
#
sub get_del_cert {
   my ($self, $main) = @_;
    
   my($certname, $cert, $certfile, $status, $t, $row, $ind, $ca);

   $ca   = $main->{'CA'}->{'actca'};

   $row = $main->{'certlist'}->selection();
   $ind = $main->{'certlist'}->get_text($row, 8);

   if(not defined $ind) {
      $main->print_info(gettext("Please select a Certificate first"));
      return;
   }

   ($cert, $status) = split(/\%/, $self->{'certlist'}->[$ind]);

   $certname = MIME::Base64::encode($cert, '');
   $certfile = $main->{'CA'}->{$ca}->{'dir'}."/certs/".$certname.".pem";

   if($status eq gettext("VALID")) {
      $main->print_warning(
            gettext("Can't delete VALID certificate!\nPlease revoke the Certificate first."));
      return;
   }

   $main->show_del_confirm($certfile, 'cert');

   return;
}

#
# now really delete the certificatefile
#
sub del_cert {
   my ($self, $main, $file) = @_;

   unlink($file);

   $main->create_mframe();

   return;
}

#
# get informations for exporting a certificate
#
sub get_export_cert {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my($ca, $ind, $row, $t, $cn, $email);

   $ca = $main->{'CA'}->{'actca'};

   if(not defined($opts)) {
      $row   = $main->{'certlist'}->selection();
      $ind   = $main->{'certlist'}->get_text($row, 8);
      $cn    = $main->{'certlist'}->get_text($row, 0);
      $email = $main->{'certlist'}->get_text($row, 1);
   
      if(not defined $ind) {
         $main->print_info(gettext("Please select a Certificate first"));
         return;
      }

      ($opts->{'cert'}, $opts->{'status'}) = 
         split(/\%/, $self->{'certlist'}->[$ind]);

      $opts->{'certname'} = MIME::Base64::encode($opts->{'cert'}, '');
      $opts->{'certfile'} = 
         $main->{'CA'}->{$ca}->{'dir'}."/certs/".$opts->{'certname'}.".pem";
      $opts->{'keyfile'}  = 
         $main->{'CA'}->{$ca}->{'dir'}."/keys/".$opts->{'certname'}.".pem";
      $opts->{'cafile'}   = $main->{'CA'}->{$ca}->{'dir'}."/cacert.pem";
      if (-f $main->{'CA'}->{$ca}->{'dir'}."/cachain.pem") {
         $opts->{'cafile'} = $main->{'CA'}->{$ca}->{'dir'}."/cachain.pem";
      }

      if($opts->{'status'} ne gettext("VALID")) {
         $t = gettext("Certificate seems not to be VALID");
         $t .= "\n";
         $t .= gettext("Export is not possible");
         $main->print_warning($t);
         return;
      }
      
      $opts->{'parsed'} = $self->parse_cert($main, $opts->{'certname'});

      if((defined($email)) && $email ne '' && $email ne ' ') {
         $opts->{'outfile'} = "/tmp/$email-cert.pem";
      }elsif((defined($cn)) && $cn ne '' && $cn ne ' ') {
         $opts->{'outfile'} = "/tmp/$cn-cert.pem";
      }else{
         $opts->{'outfile'} = "/tmp/cert.pem";
      }
      $opts->{'format'}  = 'PEM';

      $main->show_export_dialog($opts, 'cert');
      return;
   }

   if((not defined($opts->{'outfile'})) || ($opts->{'outfile'} eq '')) {
      $main->show_export_dialog($opts, 'cert');
      $main->print_warning(gettext("Please give at least the output file"));
      return;
   }

   if($opts->{'format'} eq 'P12') {
      if(not -s $opts->{'keyfile'}) {
         $t = gettext("Key is necessary for export as PKCS#12");
         $t .= "\n";
         $t .= gettext("Export is not possible!");
         $main->print_warning($t);
         return;
      }

      if(not defined($opts->{'p12passwd'})) {
         $opts->{'includeca'} = 1;
         $main->show_p12_export_dialog($opts, 'cert');
         return;
      }
   } elsif($opts->{'format'} eq 'ZIP') {
      if(not -s $opts->{'keyfile'}) {
         $t = gettext("Key is necessary for export as Zip");
         $t .= "\n";
         $t .= gettext("Export is not possible!");
         $main->print_warning($t);
         return;
      }
   }

   $self->export_cert($main, $opts); #FIXME no need for two functions

   return;
}


#
# now really export the certificate
#
sub export_cert {
   my ($self, $main, $opts) = @_;
    
   my($ca, $t, $out, $ret);

   $ca   = $main->{'CA'}->{'actca'};

   if($opts->{'format'} eq 'PEM') {
      $out = $opts->{'parsed'}->{'PEM'};
   } elsif ($opts->{'format'} eq 'DER') {
      $out = $opts->{'parsed'}->{'DER'};
   } elsif ($opts->{'format'} eq 'TXT') {
      $out = $opts->{'parsed'}->{'TEXT'};
   } elsif ($opts->{'format'} eq 'P12') {
      unlink($opts->{'outfile'});
      $ret = $main->{'OpenSSL'}->genp12(
            main      => $main,
            certfile  => $opts->{'certfile'},
            keyfile   => $opts->{'keyfile'},
            cafile    => $opts->{'cafile'},
            outfile   => $opts->{'outfile'},
            passwd    => $opts->{'passwd'},
            p12passwd => $opts->{'p12passwd'},
            includeca => $opts->{'includeca'}
            );

      if($ret == 1) {
         $t = "Wrong password given\nDecrypting Key failed\nGenerating PKCS#12 failed";
         $main->print_warning($t);
         return;
      } elsif($ret || (not -s $opts->{'outfile'})) {
         $main->print_warning(gettext("Generating PKCS#12 failed"));
         return;
      }

      $t = sprintf(gettext("Certificate and Key successfully exported to %s"), 
            $opts->{'outfile'});
      $main->print_info($t);
      return;

   } elsif ($opts->{'format'} eq "ZIP") {

      my $tmpdir    = $main->{'init'}->{'basedir'}."/tmp";
      my $tmpcert   = "$tmpdir/cert.pem";
      my $tmpkey    = "$tmpdir/key.pem";
      my $tmpcacert = "$tmpdir/cacert.pem";

      open(OUT, ">$tmpcert") || do {
         $main->print_warning(gettext("Can't create temporary file"));
         return;
      };
      print OUT $opts->{'parsed'}->{'PEM'};
      close OUT;

      # store key in temporary location
      {
      open(IN, "<$opts->{'keyfile'}") || do {
         $main->print_warning(gettext("Can't read Key file"));
         return;
      };
      my @key = <IN>;
      close IN;

      open(OUT, ">$tmpkey") || do {
         $main->print_warning(gettext("Can't create temporary file"));
         return;
      };
      print OUT @key;
      close OUT;
      }

      # store cacert in temporary location
      {
      open(IN, "<$opts->{'cafile'}") || do {
         $main->print_warning(gettext("Can't read CA certificate"));
         return;
      };
      my @cacert = <IN>;
      close IN;

      open(OUT, ">$tmpcacert") || do {
         $main->print_warning(gettext("Can't create temporary file"));
         return;
      };
      print OUT @cacert;
      close OUT;
      }

      unlink($opts->{'outfile'});
      system($main->{'init'}->{'zipbin'}, '-j', $opts->{'outfile'}, $tmpcacert, 
             $tmpkey, $tmpcert);
      my $ret = $? >> 8;

      if(not -s $opts->{'outfile'} || $ret) {
         $main->print_warning(gettext("Generating Zip file failed"));
      } else {
         $t = sprintf(
               gettext("Certificate and Key successfully exported to %s"), 
               $opts->{'outfile'});
         $main->print_info($t);
      unlink($tmpcacert);
      unlink($tmpcert);
      unlink($tmpkey);

      return;
      }

   } else {
      $t = sprintf(gettext("Invalid Format for export_cert(): %s"), 
            $opts->{'format'});
      $main->print_warning($t);
      return;
   }

   open(OUT, ">$opts->{'outfile'}") || do {
      $main->print_warning(gettext("Can't open output file: %s: %s"),
            $opts->{'outfile'}, $!);
      return;
   };

   print OUT $out;
   close OUT;
   
   $t = sprintf(gettext("Certificate successfully exported to: %s"), 
         $opts->{'outfile'});
   $main->print_info($t);

   return;
}

sub parse_cert {
   my ($self, $main, $name, $force) = @_;

   my($ca, $certfile, $x509, $parsed);

   $ca = $main->{'CA'}->{'actca'};

   if($name eq 'CA') {
      $certfile = $main->{'CA'}->{$ca}->{'dir'}."/cacert.pem";
   } else {
      $certfile = $main->{'CA'}->{$ca}->{'dir'}."/certs/".$name.".pem";
   }

   $parsed = $main->{'OpenSSL'}->parsecert(
         $main, 
         $certfile,
         $force
         );

   return($parsed);
}

1
