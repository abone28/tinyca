# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: OpenSSL.pm,v 1.22 2004/05/06 19:22:23 sm Exp $
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

package OpenSSL;

use POSIX;
use Locale::gettext;
use IPC::Open3;

sub new {
   my $self  = {};
   my $that  = shift;
   my $main  = shift;
   my $class = ref($that) || $that;

   $self->{'bin'} = $main->{'init'}->{'opensslbin'};
   my $t = sprintf("Can't execute OpenSSL: %s", $self->{'bin'});
   $main->print_error($t)
      if (! -x $self->{'bin'});

   $self->{'tmp'}  = $main->{'init'}->{'basedir'}."/tmp";

   open(TEST, "$self->{'bin'} version|");
   my $v = <TEST>;
   close(TEST);

   if($v =~ /0.9.6/) {
      $self->{'version'} = "0.9.6";
   } elsif ($v =~ /0.9.7/) {
      $self->{'version'} = "0.9.7";
   }

   bless($self, $class);
}

sub newkey {
   my $self = shift;
   my $opts = { @_ };

   my ($cmd);
   if($opts->{'algo'} eq "dsa") {
      my $param = _mktmp($self->{'tmp'}."/param");
      
      $cmd = "$self->{'bin'} dsaparam";
      $cmd .= " -out $param";
      $cmd .= " $opts->{'bits'}";
      system($cmd);

      $cmd = "$self->{'bin'} gendsa";
      $cmd .= " -des3";
      $cmd .= " -passout env:SSLPASS";
      $cmd .= " -out $opts->{'outfile'}";
      $cmd .= " $param";
      
      $ENV{'SSLPASS'} = $opts->{'pass'};
      system($cmd);
      delete($ENV{'SSLPASS'});

   } else {
      $cmd = "$self->{'bin'} genrsa";
      $cmd .= " -des3";
      $cmd .= " -passout env:SSLPASS";

      $cmd .= " -out $opts->{'outfile'}";

      $cmd .= " $opts->{'bits'}";
      $ENV{'SSLPASS'} = $opts->{'pass'};
      system($cmd);
      delete($ENV{'SSLPASS'});
   }
}

sub signreq {
   my $self = shift;
   my $opts = { @_ };

   my $cmd = "$self->{'bin'} ca -batch";
   $cmd .= " -passin env:SSLPASS";
   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -name $opts->{'caname'}" if($opts->{'caname'} ne "");
   $cmd .= " -in $opts->{'reqfile'}";
   $cmd .= " -days $opts->{'days'}";
   $cmd .= " -preserveDN";

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      $cmd .= " -keyfile $opts->{'keyfile'}";
      $cmd .= " -cert $opts->{'cacertfile'}";
      $cmd .= " -outdir $opts->{'outdir'}";
      $ENV{'SSLPASS'} = $opts->{'parentpw'};
   } else {
      $ENV{'SSLPASS'} = $opts->{'pass'};
   }

   if(defined($opts->{'sslservername'}) && $opts->{'sslservername'} ne 'none') {
      $ENV{'NSSSLSERVERNAME'} = $opts->{'sslservername'};
   }
   if(defined($opts->{'revocationurl'}) && $opts->{'revocationurl'} ne 'none') {
      $ENV{'NSREVOCATIONURL'} = $opts->{'revocationurl'};
   }
   if(defined($opts->{'renewalurl'}) && $opts->{'renewalurl'} ne 'none') {
      $ENV{'NSRENEWALURL'} = $opts->{'renewalurl'};
   }
   if($opts->{'subjaltname'} ne 'none' && 
         $opts->{'subjaltname'} ne 'emailcopy') {
      if($opts->{'subjaltnametype'} eq 'ip') {
         $ENV{'SUBJECTALTNAMEIP'} = "IP:".$opts->{'subjaltname'};
      }elsif($opts->{'subjaltnametype'} eq 'dns') {
         $ENV{'SUBJECTALTNAMEDNS'} = "DNS:".$opts->{'subjaltname'};
      }elsif($opts->{'subjaltnametype'} eq 'mail') {
         $ENV{'SUBJECTALTNAMEEMAIL'} = "email:".$opts->{'subjaltname'};
      }
   }

   # print STDERR "DEBUG call cmd: $cmd\n";
      
   my($rdfh, $wtfh);
   open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      # print STDERR "DEBUG cmd returns: $_\n";
      if($_ =~ /unable to load CA private key/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         return(1);
      } elsif($_ =~ /trying to load CA private key/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         return(2);
      } elsif($_ =~ /There is already a certificate for/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         return(3);
      } elsif($_ =~ /bad ip address/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         return(4);
      }
   }
   delete($ENV{'SSLPASS'});
   $ENV{'NSSSLSERVERNAME'}     = 'dummy';
   $ENV{'NSREVOCATIONURL'}     = 'dummy';
   $ENV{'NSRENEWALURL'}        = 'dummy';
   $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
   $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
   $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';

   my $ret = $? >> 8;

   return($ret);
}

sub revoke {
   my $self = shift;
   my $opts = { @_ };

   my $cmd = "$self->{'bin'} ca";
   $cmd .= " -passin env:SSLPASS";

   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -revoke $opts->{'infile'}";

   $ENV{'SSLPASS'} = $opts->{'pass'};
   my($rdfh, $wtfh);
   open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      if($_ =~ /unable to load CA private key/) {
         delete($ENV{'SSLPASS'});
         return(1);
      } elsif($_ =~ /trying to load CA private key/) {
         delete($ENV{'SSLPASS'});
         return(2);
      }
   }
   delete($ENV{'SSLPASS'});

   return(0);
}

sub newreq {
   my $self = shift;
   my $opts = { @_ };

   my $cmd = "$self->{'bin'} req -new";
   $cmd .= " -keyform PEM";
   $cmd .= " -outform PEM";
   $cmd .= " -passin env:SSLPASS";

   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -out $opts->{'outfile'}";
   $cmd .= " -key $opts->{'keyfile'}";
   $cmd .= " -"."$opts->{'digest'}";

   $ENV{'SSLPASS'} = $opts->{'pass'};
   #   print "DEBUG call: $cmd\n";
   open(CMD, "|$cmd");
   foreach(@{$opts->{'dn'}}) {
      # print "DEBUG: add to dn: $_\n";
      if(defined($_)) {
         print CMD "$_\n";
      } else {
         print CMD ".\n";
      }
   }
   close CMD;
   delete($ENV{'SSLPASS'});

   return;
}

sub newcert {
   my $self = shift;
   my $opts = { @_ };

   my $cmd = "$self->{'bin'} req -x509";
   $cmd .= " -keyform PEM";
   $cmd .= " -outform PEM";
   $cmd .= " -passin env:SSLPASS";

   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -out $opts->{'outfile'}";
   $cmd .= " -key $opts->{'keyfile'}";
   $cmd .= " -in $opts->{'reqfile'}";
   $cmd .= " -days $opts->{'days'}";
   $cmd .= " -"."$opts->{'digest'}";

   $ENV{'SSLPASS'} = $opts->{'pass'};
   system($cmd);
   delete($ENV{'SSLPASS'});
}

sub newcrl {
   my $self = shift;
   my $main = shift;
   my $opts = { @_ };

   my $out;

   my $tmpfile = _mktmp($self->{'tmp'}."/crl");
   my $cmd = "$self->{'bin'} ca -gencrl";
   $cmd .= " -passin env:SSLPASS";
   $cmd .= " -config $opts->{'config'}";

   $cmd .= " -out $tmpfile";
   $cmd .= " -crldays $opts->{'crldays'}";

   $ENV{'SSLPASS'} = $opts->{ 'pass'};
   my($rdfh, $wtfh);
   open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      # print STDERR "DEBUG: cmd return: $_";
      if($_ =~ /unable to load CA private key/) {
         delete($ENV{'SSLPASS'});
         return(1);
      } elsif($_ =~ /trying to load CA private key/) {
         delete($ENV{'SSLPASS'});
         return(2);
      }
   }
   my $ret = $? >> 8;
   delete($ENV{'SSLPASS'});

   return($ret) if($ret);

   my $crl = $self->parsecrl($main, $tmpfile, 1);
   unlink( $tmpfile);

   $opts->{'format'} = 'PEM' if ( !defined( $opts->{ 'format'}));
   if($opts->{'format'} eq 'PEM') {
      $out = $crl->{'PEM'};
   } elsif ($opts->{'format'} eq 'DER') {
      $out = $crl->{'DER'};
   } elsif ($opts->{'format'} eq 'TXT') {
      $out = $crl->{'TXT'};
   } else {
      $out = $crl->{'PEM'};
   }

   unlink( $opts->{'outfile'});
   open(OUT, ">$opts->{'outfile'}") or return;
   print OUT $out;
   close OUT;

   return(0);
}
   
sub parsecrl {
   my ($self, $main, $file, $force) = @_;

   my $tmp   = {};
   my (@lines, $i, $t);

   # check if crl is cached
   if($self->{'CACHE'}->{$file} && not $force) {
      return($self->{'CACHE'}->{$file});
   }

   open(IN, $file) || do {
      $t = sprintf("Can't open CRL '%s': %s", $file, $!);
      $main->print_warning($t);
      return;
   };

   # convert crl to PEM, DER and TEXT
   $tmp->{'PEM'} .= $_ while(<IN>);
   $tmp->{'TXT'}   = $self->convdata(
         'cmd'     => 'crl',
         'main'    => $main,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'TEXT'
         );
   $tmp->{'DER'} = $self->convdata(
         'cmd'     => 'crl',
         'main'    => $main,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'DER'
         );

   # get "normal infos"
   @lines = split(/\n/, $tmp->{'TXT'});
   foreach(@lines) {
      if ($_ =~ /Signature Algorithm.*: (\w+)/i) {
         $tmp->{'SIG_ALGORITHM'} = $1;
      } elsif ($_ =~ /Issuer: (.+)/i) {
         $tmp->{'ISSUER'} = $1;
         $tmp->{'ISSUER'} =~ s/,/\//g;
         $tmp->{'ISSUER'} =~ s/\/ /\//g;
         $tmp->{'ISSUER'} =~ s/^\///;
      } elsif ($_ =~ /Last Update.*: (.+)/i) {
         $tmp->{'LAST_UPDATE'} = $1;
      } elsif ($_ =~ /Next Update.*: (.+)/i) {
         $tmp->{'NEXT_UPDATE'} = $1;
      } 
   }   

   # get revoked certs
   $tmp->{'LIST'} = [];
   for($i = 0; $lines[$i] !~ /^[\s\t]*Revoked Certificates:$/i; $i++) {
      $self->{'CACHE'}->{$file} = $tmp;
      return($tmp) if ($lines[$i] =~ /No Revoked Certificates/i);
   }
   $i++;

   while($i < @lines) {
      if($lines[$i] =~ /Serial Number.*: (.+)/i) {
         my $t= {};
         $t->{'SERIAL'} = length($1)%2?"0".uc($1):uc($1);
         $i++;
         if($lines[$i] =~ /Revocation Date: (.*)/i ) {
            $t->{'DATE'} = $1;
            $i++;
            push(@{$tmp->{'LIST'}}, $t);
         } else {
            $t = sprintf("CRL seems to be corrupt: %s\n", $file);
            $main->print_warning($t);
            return;
         }
         
      } else {
         $i++;
      }
   }

   $self->{'CACHE'}->{$file} = $tmp;

   return($tmp);
}

sub parsecert {
   my ($self, $main, $file, $force) = @_;

   my $tmp   = {};
   my (@lines, @dn, $i, $c, $v, $k, $cmd, $crl, $time, $t);

   my $ca  = $main->{'CA'}->{'actca'};

   $time = time();

   $force && delete($self->{'CACHE'}->{$file});

   # check if certificate is cached
   if($self->{'CACHE'}->{$file}) {
      #  print "DEBUG: use cached certificate\n";
      return($self->{'CACHE'}->{$file});
   }
   #print "DEBUG: parse certificate\n";

   open(IN, $file) || do {
      $t = sprintf("Can't open Certificate '%s': %s", $file, $!);
      $main->print_warning($t);
      return;
   };

   # convert certificate to PEM, DER and TEXT
   $tmp->{'PEM'} .= $_ while(<IN>);
   $tmp->{'TEXT'} = $self->convdata(
         'cmd'     => 'x509',
         'main'    => $main,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'TEXT'
         );
   $tmp->{'DER'} = $self->convdata(
         'cmd'     => 'x509',
         'main'    => $main,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'DER'
         );

   # get "normal infos"
   @lines = split(/\n/, $tmp->{'TEXT'});
   foreach(@lines) {
      if($_ =~ /Serial Number.*: (.+) /i) {
         # shit, -text shows serial as decimal number :(
         # dirty fix (incompleted) --curly
         $i = sprintf( "%x", $1);
         $tmp->{'SERIAL'} = length($i)%2?"0".uc($i):uc($i);
      } elsif ($_ =~ /Signature Algorithm.*: (\w+)/i) {
         $tmp->{'SIG_ALGORITHM'} = $1;
      } elsif ($_ =~ /Issuer: (.+)/i) {
         $tmp->{'ISSUER'} = $1;
         $tmp->{'ISSUER'} =~ s/,/\//g;
         $tmp->{'ISSUER'} =~ s/\/ /\//g;
         $tmp->{'ISSUER'} =~ s/^\///;
      } elsif ($_ =~ /Not Before.*: (.+)/i) {
         $tmp->{'NOTBEFORE'} = $1;
      } elsif ($_ =~ /Not After.*: (.+)/i) {
         $tmp->{'NOTAFTER'} = $1;
      } elsif ($_ =~ /Public Key Algorithm.*: (.+)/i) {
         $tmp->{'PK_ALGORITHM'} = $1;
      } elsif ($_ =~ /Modulus \((\d+) .*\)/i) {
         $tmp->{'KEYSIZE'} = $1;
      } elsif ($_ =~ /Subject.*: (.+)/i) {
         $tmp->{'DN'} = $1;
      }
   }   

   $tmp->{'DN'} =~ s/,/\//g;
   @dn = split(/\//, $tmp->{'DN'});
   foreach(@dn) {
      s/^\s+//;
      s/\s+$//;
      ($k, $v) = split(/=/);
      if($k =~ /ou/i) {
         $tmp->{'OU'} or  $tmp->{'OU'} = [];
         push(@{$tmp->{'OU'}}, $v);
      } elsif($k eq 'emailAddress' || $k eq 'Email') {
	 $tmp->{'EMAIL'} = $v;
      } else {
         $tmp->{uc($k)} = $v;
      }
   }

   # get extensions
   $tmp->{'EXT'} = {};
   for($i = 0; $lines[$i] !~ /^[\s\t]*X509v3 extensions:$/i; $i++) {
      return($tmp) if not defined($lines[$i]);
   }
   $i++;

   while($i < @lines) {
      if(($lines[$i] =~ /^[\s\t]*[^:]+:\s*$/) ||
         ($lines[$i] =~ /^[\s\t]*[^:]+:\s+.+$/)) {
         if($lines[$i] =~ /^[\s\t]*Signature Algorithm/i) {
            $i++;
            next;
         }
         $k = $lines[$i];
         $k =~ s/[\s\t:]*$//g;
         $k =~ s/^[\s\t]*//g;
         $tmp->{'EXT'}->{$k} = [];
         $i++;
         while(($lines[$i] !~ /^[\s\t].+:\s*$/) && 
               ($lines[$i] !~ /^[\s\t]*[^:]+:\s+.+$/) &&
               ($lines[$i] !~ /^[\s\t]*Signature Algorithm/i) &&
               ($i < @lines)) {
            $v = $lines[$i];
            $v =~ s/^[\s]+//g;
            $v =~ s/[\s]+$//g;
            $i++;
            next if $v =~ /^$/;
            next if $v =~ /Signature Algorithm:/;
            my @vs = split(/,/, $v);
            foreach(@vs) {
               $_ =~ s/^\s//;
               $_ =~ s/\s$//;
               push(@{$tmp->{'EXT'}->{$k}}, $_);
            }
         }
      } else {
         $i++;
      }
   }

   # get fingerprint 
   $cmd = "$self->{'bin'} x509 -noout -fingerprint -in $file";
   open(CMD, "$cmd|");
   ($k, $v) = split(/=/, <CMD>);
   close(CMD);
   $tmp->{'FINGERPRINT'} = $v if($k =~ /MD5 Fingerprint/i);

   $tmp->{'EXPDATE'} = _get_date( $tmp->{'NOTAFTER'});

   $crl = $self->parsecrl( 
         $main,
         $main->{'CA'}->{$ca}->{'dir'}."/crl/crl.pem"
         );

   defined($crl) || $main->print_error(gettext("Can't read CRL"));

   $tmp->{'STATUS'} = gettext("VALID");

   if($tmp->{'EXPDATE'} < $time) {
      $tmp->{'STATUS'} = gettext("EXPIRED");
      # keep database up to date
      if($crl->{'ISSUER'} eq $tmp->{'ISSUER'}) {
         _set_expired($tmp->{'SERIAL'}, $main);
      }
   }
   
   foreach my $revoked (@{$crl->{'LIST'}}) {
      next if ($tmp->{'SERIAL'} ne $revoked->{'SERIAL'});
      if ($tmp->{'SERIAL'} eq $revoked->{'SERIAL'}) {
         $tmp->{'STATUS'} = gettext("REVOKED");
      }
   }

   $self->{'CACHE'}->{$file} = $tmp;

   return($tmp);
}

sub parsereq {
   my ($self, $main, $file) = @_;

   my $ca     = $main->{'CA'}->{'actca'};
   my $config = $main->{'CA'}->{$ca}->{'cnf'};
   my $tmp    = {};

   my (@lines, @dn, $i, $c, $v, $k, $cmd, $t);

   # check if request is cached
   if($self->{'CACHE'}->{$file}) {
      return($self->{'CACHE'}->{$file});
   }

   open(IN, $file) || do {
      $t = sprintf(gettext("Can't open Request file %s: %s"), $file, $!);
      $main->print_warning($t);
      return;
   };

   # convert request to PEM, DER and TEXT
   $tmp->{'PEM'} .= $_ while(<IN>);

   $tmp->{'TEXT'} = $self->convdata(
         'cmd'     => 'req',
         'main'    => $main,
         'config'  => $config,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'TEXT'
         );

   $tmp->{'DER'} = $self->convdata(
         'cmd'     => 'req',
         'main'    => $main,
         'config'  => $config,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'DER'
         );

   # get "normal infos"
   @lines = split(/\n/, $tmp->{'TEXT'});
   foreach(@lines) {
      if ($_ =~ /Signature Algorithm.*: (\w+)/i) {
         $tmp->{'SIG_ALGORITHM'} = $1;
      } elsif ($_ =~ /Public Key Algorithm.*: (.+)/i) {
         $tmp->{'PK_ALGORITHM'} = $1;
      } elsif ($_ =~ /Modulus \((\d+) .*\)/i) {
         $tmp->{'KEYSIZE'} = $1;
      } elsif ($_ =~ /Subject.*: (.+)/i) {
         $tmp->{'DN'} = $1;
      } elsif ($_ =~ /Version: \d.*/i) {
         $tmp->{'TYPE'} = 'PKCS#10';
      }
   }   

   $tmp->{'DN'} =~ s/,/\//g;
   @dn = split(/\//, $tmp->{'DN'});
   foreach(@dn) {
      s/^\s+//;
      s/\s+$//;
      ($k, $v) = split(/=/);
      if($k =~ /ou/i) {
         $tmp->{'OU'} or  $tmp->{'OU'} = [];
         push(@{$tmp->{'OU'}}, $v);
      } else {
         if($k =~ /emailaddress/i) {
            $tmp->{'EMAIL'} = $v;
         } else {
            $tmp->{uc($k)} = $v;
         }
      }
   }

   # get extensions
   $tmp->{'EXT'} = {};
   for($i = 0; 
        defined($lines[$i]) && 
        $lines[$i] !~ /^[\s\t]*Requested extensions:$/i;
        $i++) {
      return($tmp) if not defined($lines[$i]);
   }
   $i++;

   while($i < @lines) {
      if($lines[$i] =~ /^[\s\t]*[^:]+:\s*$/) {
         $k = $lines[$i];
         $k =~ s/[\s\t:]*$//g;
         $k =~ s/^[\s\t]*//g;
         $tmp->{'EXT'}->{$k} = [];
         $i++;
         while($lines[$i] !~ /^[\s\t].+:\s*$/ && $i < @lines) {
            $v = $lines[$i];
            $v =~ s/^[\s]+//g;
            $v =~ s/[\s]+$//g;
            $i++;
            next if $v =~ /^$/;
            next if $v =~ /Signature Algorithm:/;
            my @vs = split(/,/, $v);
            foreach(@vs) {
               $_ =~ s/^\s//;
               $_ =~ s/\s$//;
               push(@{$tmp->{'EXT'}->{$k}}, $_);
            }
         }
      } else {
         $i++;
      }
   }

   $self->{'CACHE'}->{$file} = $tmp;

   return($tmp);
}

sub convdata {
   my $self = shift;
   my $opts = { @_ };
   
   my $tmp  = '';
   my $file = _mktmp($self->{'tmp'}."/data");

   my $cmd = "$self->{'bin'} $opts->{'cmd'}";
   $cmd .= " -config $opts->{'config'}" if(defined($opts->{'config'}));
   $cmd .= " -inform $opts->{'inform'}";
   $cmd .= " -out $file";
   if($opts->{'outform'} eq "TEXT") {
      $cmd .= " -text -noout";
   } else {
      $cmd .= " -outform $opts->{'outform'}";
   }

   my($rdfh, $wtfh);
   open3($wtfh, $rdfh, $rdfh, $cmd);
   print $wtfh "$opts->{'data'}\n";
   while(<$rdfh>){
      print STDERR "DEBUG: cmd ret: $_";
   };

   open(IN, $file) || do {
      my $t = sprintf(gettext("Can't open file %s: %s"), $file, $!);
      $opts->{'main'}->print_warning($t);
      return;
   };
   $tmp .= $_ while(<IN>);
   close(IN);

   unlink($file);

   return($tmp);
}

sub convkey {
   my $self = shift;
   my $opts = { @_ };

   my $tmp  = '';
   my $file = _mktmp($self->{'tmp'}."/key");

   my $cmd = "$self->{'bin'}";

   print STDERR "DEBUG: got type: $opts->{'type'}\n";
  
   if($opts->{'type'} eq "RSA") {
      $cmd .= " rsa";
   } elsif($opts->{'type'} eq "DSA") {
      $cmd .= " dsa";
   }

   $cmd .= " -inform $opts->{'inform'}";
   $cmd .= " -outform $opts->{'outform'}";
   $cmd .= " -in $opts->{'keyfile'}";
   $cmd .= " -out $file";

   $cmd .= " -passin env:SSLPASS";
   $cmd .= " -passout env:SSLPASSOUT -des3" if(not $opts->{'nopass'});

   $ENV{'SSLPASS'}    = $opts->{'pass'};
   $ENV{'SSLPASSOUT'} = $opts->{'pass'} if(not $opts->{'nopass'});
   
   my($rdfh, $wtfh);
   open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      if($_ =~ /unable to load key/) {
         delete($ENV{'SSLPASS'});
         delete($ENV{'SSLPASSOUT'});
         return(1);
      }
   }

   delete($ENV{'SSLPASS'});
   delete($ENV{'SSLPASSOUT'});

   open(IN, $file) || return(undef);
   $tmp .= $_ while(<IN>);
   close(IN);

   unlink($file);

   return($tmp);
}

sub genp12 {
   my $self = shift;
   my $opts = { @_ };

   my($main, $cmd);
   
   $main = $opts->{'main'};

   $cmd = "$self->{'bin'} pkcs12 -export";
   $cmd .= " -out $opts->{'outfile'}";
   $cmd .= " -in $opts->{'certfile'}";
   $cmd .= " -inkey $opts->{'keyfile'}";
   $cmd .= " -passout env:P12PASS";
   $cmd .= " -passin env:SSLPASS";
   $cmd .= " -certfile $opts->{'cafile'}" if($opts->{'includeca'});

   $ENV{'P12PASS'} = $opts->{'p12passwd'};
   $ENV{'SSLPASS'} = $opts->{'passwd'};
   my($rdfh, $wtfh);
   open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      if($_ =~ /Error loading private key/) {
         delete($ENV{'SSLPASS'});
         delete($ENV{'P12PASS'});
         return(1);
      }
   }
   my $ret = $? >> 8;

   delete($ENV{'P12PASS'});
   delete($ENV{'SSLPASS'});

   return($ret) if($ret);

   return(0);
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

sub _set_expired {
   my ($serial, $main) =@_;
   
   my $ca = $main->{'CA'}->{'actca'};

   my $index = $main->{'CA'}->{$ca}->{'dir'}."/index.txt";

   open(IN, "<$index") || do {
      my $t = sprintf(gettext("Can't read index %s: %s"), $index, $!);
      $main->print_warning($t);
      return;
   };

   my @lines = <IN>;

   close IN;

   open(OUT, ">$index") || do {
      my $t = sprintf(gettext("Can't write index %s: %s"), $index, $!);
      $main->print_warning($t);
      return;
   };

   foreach my $l (@lines) {
      if($l =~ /\t$serial\t/) {
         $l =~ s/^V/E/;
      }
      print OUT $l;
   }

   close OUT;

   return;
}

sub _get_date {
   my $string = shift;
         
   $string =~ s/  / /g;
            
   my @t1 = split(/ /, $string);
   my @t2 = split(/:/, $t1[2]);

   $t1[0] = _get_index($t1[0]);
                              
   my $ret = Time::Local::timelocal($t2[2],$t2[1],$t2[0],$t1[1],$t1[0],$t1[3]);

   return($ret);
}
   
sub _get_index {
   my $m = shift;

   my @a = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);

   for(my $i = 0; $a[$i]; $i++) {
      return $i if($a[$i] eq $m);
   }
}
   
1
