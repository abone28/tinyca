# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: KEY.pm,v 1.13 2004/05/11 18:33:59 sm Exp $
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

package KEY;

use POSIX;
use Locale::gettext;

sub new {
   my $self = {};
   my $that = shift;
   my $class = ref($that) || $that;

   bless($self, $class);
}

#
# get name of keyfile to delete
#
sub get_del_key {
   my ($self, $main) = @_;

   my($keyname, $key, $keyfile, $row, $ind, $ca, $type);

   $ca   = $main->{'CA'}->{'actca'};

   $row = $main->{'keylist'}->selection(); 
   $ind = $main->{'keylist'}->get_text($row, 8);

   if(not defined $ind) {
      $main->print_info(gettext("Please select a Key first"));
      return;
   }

   ($key, $type) = split(/%/, $self->{'keylist'}->[$ind]);

   $keyname = MIME::Base64::encode($key, '');

   $keyfile = $main->{'CA'}->{$ca}->{'dir'}."/keys/".$keyname.".pem";

   if(not -s $keyfile) {
      $main->print_warning(gettext("Key file not found:".$keyfile));
      return;
   }

   $main->show_del_confirm($keyfile, 'key');

   return;
}

#
# now really delete the key
#
sub del_key {
   my ($self, $main, $file) = @_;

   unlink($file);

   $main->create_mframe();

   return;
}

#
# read keys in directory into list
#
sub read_keylist {
   my ($self, $main) = @_;

   my ($f, $modt, $tmp, $ca, $keydir, $keylist);

   $ca     = $main->{'CA'}->{'actca'};
   $keydir = $main->{'CA'}->{$ca}->{'dir'}."/keys";
   $keylist = [];

   $modt = (stat($keydir))[9];

   if(defined($self->{'lastread'}) &&
      $self->{'lastread'} >= $modt) { 
      return(0); 
   }

   opendir(DIR, $keydir) || do {
      $main->print_warning(gettext("Can't open key directory"));
      return(0);
   };

   while($f = readdir(DIR)) {
      next if $f =~ /^\./;
      $f =~ s/\.pem//;
      $tmp = MIME::Base64::decode($f);
      next if not defined($tmp);
      next if $tmp eq "";
      $tmp = _check_key($main, $keydir."/".$f.".pem", $tmp);
      push(@{$keylist}, $tmp);
   }
   @{$keylist} = sort(@{$keylist});
   closedir(DIR);

   $self->{'keylist'} = $keylist;

   $self->{'lastread'} = time();
   return(1);  # got new list
}

#
# get the information to export the key
#
sub get_export_key {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my($ca, $ind, $row, $t, $out, $cn, $email, $ret);
   
   $ca = $main->{'CA'}->{'actca'};

   if(not defined($opts)) {
      $row   = $main->{'keylist'}->selection();
      $ind   = $main->{'keylist'}->get_text($row, 8);
      $cn    = $main->{'keylist'}->get_text($row, 0);
      $email = $main->{'keylist'}->get_text($row, 1);

      if(not defined $ind) {
         $main->print_info(gettext("Please select a Key first"));
         return;
      }

      ($opts->{'key'}, $opts->{'type'}) = 
                                    split(/%/, $self->{'keylist'}->[$ind]);

      $opts->{'keyname'}  = MIME::Base64::encode($opts->{'key'}, '');
      $opts->{'keyfile'}  = 
         $main->{'CA'}->{$ca}->{'dir'}."/keys/".$opts->{'keyname'}.".pem";
      
      # set some defaults
      $opts->{'nopass'}  = 0;
      $opts->{'format'}  = 'PEM';
      if((defined($email)) && $email ne '' && $email ne ' ') {
         $opts->{'outfile'} = "/tmp/$email-key.pem";
      }elsif((defined($cn)) && $cn ne '' && $cn ne ' ') {
         $opts->{'outfile'} = "/tmp/$cn-key.pem";
      }else{
         $opts->{'outfile'} = "/tmp/key.pem";
      }

      $main->show_export_dialog($opts, 'key');
      return;
   }

   if((not defined($opts->{'outfile'})) || ($opts->{'outfile'} eq '')) {
      $main->show_export_dialog($opts, 'key');
      $main->print_warning(gettext("Please give at least the output file"));
      return;
   }

   if($opts->{'nopass'} && $opts->{'format'} eq 'P12') {
      $main->show_export_dialog($opts, 'key');
      $main->print_warning(gettext("Can't export PKCS#12 without passphrase"));
      return;
   }

   if(($opts->{'nopass'} || $opts->{'format'} eq 'DER') && 
      ((not defined($opts->{'passwd'})) || ($opts->{'passwd'} eq ''))) {
      $main->show_key_nopasswd_dialog($opts);
      return;
   }

   if(($opts->{'format'} eq 'PEM') || ($opts->{'format'} eq 'DER')) {
      unless(($opts->{'format'} eq 'PEM') && not $opts->{'nopass'}) {
         $out = $main->{'OpenSSL'}->convkey(
               'main'    => $main,
               'type'    => $opts->{'type'},
               'inform'  => 'PEM',
               'outform' => $opts->{'format'},
               'nopass'  => $opts->{'nopass'},
               'pass'    => $opts->{'passwd'},
               'keyfile' => $opts->{'keyfile'}
               );

         if(not defined($out)) {
            $main->print_warning( 
               gettext("Converting failed, Export not possible"));
            return;
         } elsif($out == 1) {
            $t = gettext("Wrong password given\nDecrypting of the Key failed\nExport is not possible");
            $main->print_warning($t);
            return;
         }
      }

      if(($opts->{'format'} eq 'PEM') && not $opts->{'nopass'}) {
         open(IN, "<$opts->{'keyfile'}") || do {
            $t = sprintf(gettext("Can't open Key file: %s: %s"), 
                  $opts->{'keyfile'}, $!);
            $main->print_warning($t);
            return;
         };
         $out .= $_ while(<IN>);
         close(IN);
      }

      open(OUT, ">$opts->{'outfile'}") || do {
            $t = sprintf(gettext("Can't open output file: %s: %s"), 
                  $opts->{'outfile'}, $!);
         $main->print_warning($t);
         return;
      };

      print OUT $out;
      close(OUT);

      $t = sprintf(gettext("Key succesfully exported to %s"), 
            $opts->{'outfile'});
      $main->print_info($t);
      return;

   } elsif ($opts->{'format'} eq 'P12') {
      $opts->{'certfile'} = 
         $main->{'CA'}->{$ca}->{'dir'}."/certs/".$opts->{'keyname'}.".pem";
      $opts->{'cafile'}   = $main->{'CA'}->{$ca}->{'dir'}."/cacert.pem";
      if (-f $main->{'CA'}->{$ca}->{'dir'}."/cachain.pem") {
        $opts->{'cafile'} = $main->{'CA'}->{$ca}->{'dir'}."/cachain.pem";
      }

      if(not -s $opts->{'certfile'}) {
         $t = gettext("Certificate is necessary for export as PKCS#12");
         $t .= "\n";
         $t .= gettext("Export is not possible!");
         $main->print_warning($t);
         return;
      }

      if(not defined($opts->{'p12passwd'})) {
         $opts->{'includeca'} = 1;
         $main->show_p12_export_dialog($opts, 'key');
         return;
      }

      unlink($opts->{'outfile'});
      $ret = $main->{'OpenSSL'}->genp12(
            main      => $main,
            type      => $opts->{'type'},
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
      $opts->{'certfile'} = 
         $main->{'CA'}->{$ca}->{'dir'}."/certs/".$opts->{'keyname'}.".pem";
      if(not -s $opts->{'certfile'}) {
         $t = gettext("Certificate is necessary for export as Zip file");
         $t .= "\n";
         $t .= gettext("Export is not possible!");
         $main->print_warning($t);
         return;
      }

      $opts->{'parsed'} = 
         $main->{'CERT'}->parse_cert($main, $opts->{'keyname'});

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
      $opts->{'cafile'} = $main->{'CA'}->{$ca}->{'dir'}."/cacert.pem";
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
      }
      unlink($tmpcacert);
      unlink($tmpcert);
      unlink($tmpkey);

      return;

   } else {
      $t = sprintf(gettext("Invalid format for export requested: %s"), 
            $opts->{'format'});
      $main->print_warning($t);
      return;
   }

   $main->print_warning(gettext("Something Failed ??"));

   return;
}

# check if its a dsa or rsa key
sub _check_key {
   my ($main, $file, $name) = @_;

   my ($t, $type);

   open(KEY, "<$file") || do {
      $t = sprintf(gettext("Can't open Key file: %s: %s"), 
            $file, $!);
      $main->print_warning($t);
      return;
   };

   while(<KEY>) {
      if(/RSA PRIVATE KEY/i) {
         $type = "RSA";
         last;
      } elsif(/DSA PRIVATE KEY/i) {
         $type = "DSA";
         last;
      }
   }
   close(KEY);

   if($type ne "") {
      $name .= "%".$type;
   }

   return($name);
}

1

#
# $Log: KEY.pm,v $
# Revision 1.13  2004/05/11 18:33:59  sm
# corrected generation of exportfile names
#
# Revision 1.12  2004/05/06 19:22:23  sm
# added display and export for DSA and RSA keys
#
# Revision 1.11  2004/05/05 16:05:28  sm
# added patch for cachain from Olaf Gellert
#
# Revision 1.10  2004/05/02 18:39:30  sm
# added possibility to create SubCA
# add new section to config for that
#
# Revision 1.8  2003/08/27 21:34:05  sm
# some more errorhandling
#
# Revision 1.7  2003/08/22 20:36:56  sm
# code cleanup
#
# Revision 1.6  2003/08/19 15:49:07  sm
# code cleanup
#
# Revision 1.5  2003/08/16 22:05:24  sm
# first release with Gtk-Perl
#
# Revision 1.3  2003/08/13 20:38:51  sm
# functionality done
#
# Revision 1.2  2003/08/13 19:39:37  sm
# rewrite for Gtk
#
# Revision 1.8  2003/07/04 22:58:58  sm
# first round of the translation is done
#
# Revision 1.7  2003/07/03 20:59:03  sm
# a lot of gettext() inserted
#
# Revision 1.6  2003/06/26 23:28:35  sm
# added zip functions
#
# Revision 1.5  2003/06/23 20:11:30  sm
# some new texts from ludwig.nussel@suse.de
#
# Revision 1.4  2002/10/04 09:21:04  sm
# skip empty lines when decoding failed
#
# Revision 1.3  2002/10/04 08:46:45  sm
# fixed bug exporting keys in PEM format
#
# Revision 1.2  2002/09/27 19:47:06  sm
# Changed call to convkey() from open(...) to system(...)
#
#
