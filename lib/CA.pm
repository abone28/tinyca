# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: CA.pm,v 1.18 2004/05/05 20:59:42 sm Exp $
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

package CA;

use POSIX;
use Locale::gettext;

sub new {
   my $that = shift;
   my $self = {};

   my $class = ref($that) || $that;

   $self->{'init'} = shift;

   if(not -d $self->{'init'}->{'basedir'}) {
      print "create basedir: $self->{'init'}->{'basedir'}\n";
      mkdir($self->{'init'}->{'basedir'}, 0700);
   }

   if(not -d $self->{'init'}->{'basedir'}."/tmp") {
      print "create temp dir: $self->{'init'}->{'basedir'}/tmp\n";
      mkdir($self->{'init'}->{'basedir'}."/tmp", 0700);
   }

   opendir(DIR, $self->{'init'}->{'basedir'}) || do {
      print gettext("error: can't open basedir: ").$!;
      exit(1);
   };

   $self->{'calist'} = [];

      while(my $ca = readdir(DIR)) { 
         chomp($ca);
         next if $ca eq ".";
         next if $ca eq "..";
         next if $ca eq "tmp";

         my $dir = $self->{'init'}->{'basedir'}."/".$ca;
         next unless -d $dir;
         next unless -s $dir."/cacert.pem";
         next unless -s $dir."/cacert.key";
         push(@{$self->{'calist'}}, $ca);
         @{$self->{'calist'}} = sort(@{$self->{'calist'}});
         $self->{$ca}->{'dir'} = $dir;
         $self->{$ca}->{'cnf'} = $dir."/openssl.cnf";
      }
      closedir(DIR);

   bless($self, $class);
}

#
# see if the ca can be opened without asking the user
# or show the open dialog
#
sub get_open_name {
   my ($self, $main, $opts) = @_;

   my ($ind);

   if((not defined($opts->{'name'})) || ($opts->{'name'} eq "")) {
      # if only one CA is defined, open it without prompting
      if($#{$self->{'calist'}} == 0) {
         $opts->{'name'} = $self->{'calist'}->[0];
         $self->open_ca($main, $opts);
      } else {
         $main->show_select_ca_dialog('open');
      }
   }
}

#
# open the ca with the given name
#
sub open_ca {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my ($i, $cnf, @lines, $oldca, $index, $bak, $t);

   $main->{'bar'}->set_status(gettext("  Opening CA: ").$opts->{'name'});

   if(!exists($self->{$opts->{'name'}})) {
      $main->print_warning(gettext("Invalid CA selected"));
      return;
   }

   # selected CA is already open
   return if ((defined($self->{'actca'})) &&
              ($opts->{'name'} eq $self->{'actca'}));

   $self->{'actca'} = $opts->{'name'};

   # update config (necessary for update from old tinyca)
   $cnf =  $self->{$opts->{'name'}}->{'cnf'};
   open(IN, "<$cnf");
   @lines = <IN>;
   close(IN);
   for($i = 0; $lines[$i]; $i++) {
      $lines[$i] =~ s/private\/cakey.pem/cacert.key/;
   }
   open(OUT, ">$cnf");
   print OUT @lines;
   close(OUT);

   $main->{'mw'}->set_title( "Tiny CA Management $main->{'version'}".
                             " - $self->{'actca'}"
         );

   $main->{'CERT'}->{'lastread'} = 0;
   $main->{'REQ'}->{'lastread'}  = 0;
   $main->{'KEY'}->{'lastread'}  = 0;

   $main->{'Openssl'} = undef;
   $main->{'bar'}->set_status(gettext("  Initializing OpenSSL"));
   $main->{'Openssl'} = OpenSSL->new($main);

   $index = $main->{'CA'}->{$opts->{'name'}}->{'dir'}."/index.txt";

   $main->{'bar'}->set_status(gettext("  Check for CA Version"));
   open(INDEX, "+<$index") || do {
      $main->print_error(gettext("Can't open index file: ".$!));
      return;
   };

   while(<INDEX>) {
      if(/Email=/) {
         $oldca = 1;
         last;
      }
   }
   close(INDEX);

   if($oldca && ($main->{'OpenSSL'}->{'version'} eq "0.9.7") && 
         !$opts->{'noconv'} && !$opts->{'doconv'}) {
      $main->{'bar'}->set_status(gettext("  Convert CA"));
      $self->{'actca'} = undef;
      $main->show_ca_convert_dialog($opts);
      return;
   }

   if($opts->{'doconv'}) {
      open(INDEX, "+<$index") || do {
         $main->print_error(gettext("Can't open index file: ".$!));
         return;
      };
      $bak = $index.".bak";
      open(BAK, "+>$bak") || do {
         $main->print_error(gettext("Can't open index backup: ").$!);
         return;
      };
      seek(INDEX, 0, 0);
      while(<INDEX>) {
         print BAK;
      }
      seek(INDEX, 0, 0);
      truncate(INDEX, 0);
      seek(BAK, 0, 0);
      while(<BAK>) {
         $_ =~ s/Email=/emailAddress=/;
         print INDEX;
      }
      close(INDEX);
      close(BAK);

      $t = gettext("This CA is converted for openssl 0.9.7x now.");
      $t .= "\n";
      $t .= gettext("You will find a backup copy of the index file at: ");
      $t .= $bak;

      $main->print_info($t);
   }

   $main->{'bar'}->set_status(gettext("  Read Configuration"));
   $main->{'TCONFIG'}->init_config($main, $opts->{'name'});

   $main->{'bar'}->set_status(gettext("  Create GUI"));
   $main->create_mframe();

   $main->{'bar'}->set_status(gettext("  Create Toolbar"));
   $main->create_toolbar('ca');

   $main->{'nb'}->set_page(0);

   $main->{'bar'}->set_status(gettext("  Actual CA: ").$self->{'actca'});

   return;
}

#
# get name for deleting a CA
#
sub get_ca_delete {
   my ($self, $main, $name) = @_;

   if(!defined($name)) {
      $main->show_select_ca_dialog('delete');
      return;
   }elsif(!exists($self->{$name})) {
      $main->show_select_ca_dialog('delete');
      $main->print_warning(gettext("Invalid CA selected"));
      return;
   }else {
      $self->delete_ca($main, $name);
   }

   return;
}

#
# delete given CA
#
sub delete_ca {
   my ($self, $main, $name, $box) = @_;

   my ($ind, @tmp, $t);

   $box->destroy() if(defined($box));

   _rm_dir($self->{$name}->{'dir'});

   if((defined($self->{'actca'})) && 
      ($name eq $self->{'actca'})) { 
      $self->{'actca'} = undef;
   }
   
   $main->{'cabox'}->destroy() if(defined($main->{'cabox'}));
   delete($main->{'cabox'});

   $main->{'reqbox'}->destroy() if(defined($main->{'reqbox'}));
   delete($main->{'reqbox'});

   $main->{'keybox'}->destroy() if(defined($main->{'keybox'}));
   delete($main->{'keybox'});

   $main->{'certbox'}->destroy() if(defined($main->{'certbox'}));
   delete($main->{'certbox'});

   for(my $i = 0; $i < 4; $i++) {
      $main->{'nb'}->remove_page($i);
   }

   $main->{'cabox'}->destroy() if(defined($main->{'cabox'}));
   delete($main->{'cabox'});

   $main->{'reqbox'}->destroy() if(defined($main->{'reqbox'}));
   delete($main->{'reqbox'});

   $main->{'keybox'}->destroy() if(defined($main->{'keybox'}));
   delete($main->{'keybox'});

   $main->{'certbox'}->destroy() if(defined($main->{'certbox'}));
   delete($main->{'certbox'});

   foreach(@{$self->{'calist'}}) {
      next if $_ eq $name;
      push(@tmp, $_);
   }
   $self->{'calist'} = \@tmp;


   delete($self->{$name});

   $main->create_mframe();

   $t = sprintf(gettext("CA: %s deleted"), $name);
   $main->print_info($t);

   return;
}

#
# check if all data for creating a ca is available
#
sub get_ca_create {
   my ($self, $main, $opts, $box, $mode) = @_;

   $box->destroy() if(defined($box));

   my ($name, $action, $index, $serial, $t, $parsed);

   if(!(defined($opts))) { 
      $opts = {};
      $opts->{'days'} = 3650; # set default to 10 years
      $opts->{'bits'} = 2048;
      $opts->{'digest'} = 'sha1';

      if(defined($mode) && $mode eq "sub") { # create SubCA, use defaults
         $opts->{'parentca'} = $main->{'CA'}->{'actca'};
         
         $parsed = $main->{'CERT'}->parse_cert($main, 'CA');
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
      }
      
      $main->show_ca_dialog($opts, $mode);
      return;
   }

   if(defined($mode) && $mode eq "sub") {
      if(not defined($opts->{'parentpw'})) {
         $main->show_ca_dialog($opts, $mode);
         $main->print_warning(
             gettext("Password of parent CA is needed for creating a Sub CA"));
         return;
      }
   }

   if((not defined($opts->{'name'})) || 
	   ($opts->{'name'} eq "") ||
	   ($opts->{'name'} =~ /\s/)) { 
      $main->show_ca_dialog($opts, $mode);
      $main->print_warning(gettext("Name must be filled in and must")
                          .gettext(" not contain Spaces"));
      return;
   }

   if((not defined($opts->{'C'})) ||
      ($opts->{'C'} eq "") ||
      (not defined($opts->{'CN'})) ||
      ($opts->{'CN'} eq "") ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'passwd'} eq "")) { 
      $main->show_ca_dialog($opts, $mode);
      $main->print_warning(gettext("Please specify at least Common Name, ")
                           .gettext("Country and Password"));
      return;
   }

   if((not defined($opts->{'passwd2'})) ||
      $opts->{'passwd'} ne $opts->{'passwd2'}) { 
      $main->show_ca_dialog($opts, $mode);
      $main->print_warning(gettext("Passwords don't match"));
      return;
   }

   $opts->{'C'} = uc($opts->{'C'});

   if(length($opts->{'C'}) != 2) { 
      $main->show_ca_dialog($opts, $mode);
      $main->print_warning(gettext("Country must be exact 2 letter code"));
      return;
   }

   $name = $opts->{'name'};

   $t = sprintf(gettext("CA: %s already exists"), $name);
   if(defined($self->{$name})) { 
      $main->show_ca_dialog($opts, $mode);
      $main->print_warning($t);
      return;
   }

   $self->create_ca_env($main, $opts, $mode);

   return;
}

#
# create a new CA, environment: dirs, etc.
#
sub create_ca_env {
   my ($self, $main, $opts, $mode) = @_;

   my ($name, $t, $index, $serial);

   $name = $opts->{'name'};

   if((!defined($name)) || $name eq '') {
      $main->print_error(gettext("No CA name given"));
      return;
   }
 
   # create directories
   $self->{$name}->{'dir'} = $self->{'init'}->{'basedir'}."/".$name;

   mkdir($self->{$name}->{'dir'}, 0700) || do { 
      $main->print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/req", 0700) || do { 
      $main->print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/keys", 0700) || do { 
      $main->print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/certs", 0700) || do { 
      $main->print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/crl", 0700) || do { 
      $main->print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/newcerts", 0700) || do { 
      $main->print_error(gettext("Can't create directory: ").$!);
      return;
   };

   # create configuration file
   my $in  = $self->{'init'}->{'templatedir'}."/openssl.cnf";
   my $out = $self->{$name}->{'dir'}."/openssl.cnf";

   open(IN, "<$in") || do {
      $t = sprintf(gettext("Can't open template file %s %s"), $in, $!);
      $main->print_error($t);
      return;
   };
   open(OUT, ">$out") || do {
      $t = sprintf(gettext("Can't open output file: %s: %s"),$out, $!);
      $main->print_error($t);
      return;
   };
   while(<IN>) {
      s/\%dir\%/$self->{$name}->{'dir'}/;
      print OUT;
   }
   close IN;
   close OUT;
   $self->{$name}->{'cnf'} = $out;

   $main->{'TCONFIG'}->init_config($main, $name);

   # create some more files
   $index = $self->{$name}->{'dir'}."/index.txt";
   open(OUT, ">$index") || do {
      $main->print_error(gettext("Can't open index file: ").$!);
      return;
   };
   close OUT;

   $serial = $self->{$name}->{'dir'}."/serial";
   open(OUT, ">$serial") || do {
      $main->print_error(gettext("Can't write serial file: ").$!);
      return;
   };
   print OUT "01";
   close OUT;

   if(defined($mode) && $mode eq "sub") {
      $self->create_ca($main, $opts, undef, $mode);
   } else {
      $main->show_config_ca($opts, $mode);
   }

   return;
}

#
# now create the CA certificate and CRL
#
sub create_ca {
   my ($self, $main, $opts, $box, $mode, $name) = @_;

   my ($fname, $t, $index, $serial, $ca);

   $ca = $self->{'actca'};

   $box->destroy() if(defined($box));

   $name = $opts->{'name'};

   if((!defined($name)) || $name eq '') {
      $main->print_error(gettext("No CA name given"));
      return;
   }

   # create CA certifikate
   $main->{'OpenSSL'}->newkey( 
         'bits'    => $opts->{'bits'},
         'outfile' => $self->{$name}->{'dir'}."/cacert.key",
         'pass'    => $opts->{'passwd'}
         );
   
   if (not -s $self->{$name}->{'dir'}."/cacert.key") {
      $main->print_warning(gettext("Generating key failed"));
      _rm_dir($self->{$name}->{'dir'});
      delete($self->{$name});
      return;
   }

   $main->{'OpenSSL'}->newreq( 
         'config'  => $self->{$name}->{'cnf'},
         'outfile' => $self->{$name}->{'dir'}."/cacert.req",
         'digest'   => $opts->{'digest'},
         'pass'    => $opts->{'passwd'},
         'dn'      => [ $opts->{'C'}, 
                        $opts->{'ST'},
                        $opts->{'L'},
                        $opts->{'O'},
                        $opts->{'OU'},
                        $opts->{'CN'},
                        $opts->{'EMAIL'},
                        '',
                        ''
                        ],
         'keyfile' => $self->{$name}->{'dir'}."/cacert.key"
         );

   $fname = _gen_name($opts);

   $opts->{'reqname'} = MIME::Base64::encode($fname, '');
   
   if (not -s $self->{$name}->{'dir'}."/cacert.req") {
      unlink($self->{$name}->{'dir'}."/cacert.key");
      unlink($self->{$name}->{'dir'}."/cacert.req");
      $main->print_warning(gettext("Generating Request failed"));
      _rm_dir($self->{$name}->{'dir'});
      delete($self->{$name});
      return;
   } else {
      open(IN, "<$self->{$name}->{'dir'}"."/cacert.req") || do {
         $main->print_warning(gettext("Can't read Certificate"));
         return;
      };
      open(OUT, ">$self->{$ca}->{'dir'}"."/req/".$opts->{'reqname'}.".pem") || do {
         $main->print_warning(gettext("Can't write Certificate"));
         return;
      };
      print OUT while(<IN>);
      close IN; close OUT;

      open(IN, "<$self->{$name}->{'dir'}"."/cacert.key") || do {
         $main->print_warning(gettext("Can't read Certificate"));
         return;
      };
      open(OUT, ">$self->{$ca}->{'dir'}"."/keys/".$opts->{'reqname'}.".pem") || do {
         $main->print_warning(gettext("Can't write Certificate"));
         return;
      };
      print OUT while(<IN>);
      close IN; close OUT;
   }

   if(defined($mode) && $mode eq "sub") {
      $main->{'REQ'}->sign_req(
            $main,
            {
            'mode'       => "sub",
            'config'     => $self->{$name}->{'cnf'},
            'outfile'    => $self->{$name}->{'dir'}."/cacert.pem",
            'reqfile'    => $self->{$name}->{'dir'}."/cacert.req",
            'outdir'     => $self->{$ca}->{'dir'}."/newcerts/",
            'keyfile'    => $self->{$ca}->{'dir'}."/cacert.key",
            'cacertfile' => $self->{$ca}->{'dir'}."/cacert.pem",
            'pass'       => $opts->{'passwd'},
            'days'       => $opts->{'days'},
            'parentpw'   => $opts->{'parentpw'},
            'reqname'    => $opts->{'reqname'}
            }
            );
   } else {
      $main->{'OpenSSL'}->newcert( 
            'config'  => $self->{$name}->{'cnf'},
            'outfile' => $self->{$name}->{'dir'}."/cacert.pem",
            'keyfile' => $self->{$name}->{'dir'}."/cacert.key",
            'reqfile' => $self->{$name}->{'dir'}."/cacert.req",
            'digest'  => $opts->{'digest'},
            'pass'    => $opts->{'passwd'},
            'days'    => $opts->{'days'}
            );
   }
   
   if (not -s $self->{$name}->{'dir'}."/cacert.pem") {
      $main->print_warning(gettext("Generating certificate failed"));
      _rm_dir($self->{$name}->{'dir'});
      delete($self->{$name});
      return;
   }

   unlink($self->{$name}->{'dir'}."/cacert.req");

   if(defined($mode) && $mode eq "sub") {
     # create file containing chain of ca certificates
     my $in;
     if (-f $self->{$ca}->{'dir'}."/cachain.pem") {
       $in   = $self->{$ca}->{'dir'}."/cachain.pem";
     } else {
       $in   = $self->{$ca}->{'dir'}."/cacert.pem";
     }
     my $out  = $self->{$name}->{'dir'}."/cachain.pem";

     open(IN, "<$in") || do {
        $t = sprintf(gettext("Can't open ca certificate file %s %s"), $in, $!);
        $main->print_warning($t);
        _rm_dir($self->{$name}->{'dir'});
        delete($self->{$name});
        return;
     };
     open(OUT, ">$out") || do {
        $t = sprintf(gettext("Can't create certificate chain file: %s: %s"),$out, $!);
        $main->print_warnin($t);
        _rm_dir($self->{$name}->{'dir'});
        delete($self->{$name});
        return;
     };
     while(<IN>) {
        print OUT;
     }
     close IN;

     # now append the certificate of the created SubCA
     $in  = $self->{$name}->{'dir'}."/cacert.pem";
     open(IN, "<$in") || do {
        $t = sprintf(gettext("Can't open ca certificate file %s %s"), $in, $!);
        $main->print_warning($t);
        _rm_dir($self->{$name}->{'dir'});
        delete($self->{$name});
        return;
     };

     while(<IN>) {
        print OUT;
     }
     close OUT;
   }

   $main->{'OpenSSL'}->newcrl(
         $main,
         config  => $self->{$name}->{'cnf'},
         pass    => $opts->{'passwd'},
         crldays => $main->{'TCONFIG'}->{'server_ca'}->{'default_crl_days'},
         outfile => $self->{$name}->{'dir'}."/crl/crl.pem",
         format  => 'PEM'
         );

   if (not -s $self->{$name}->{'dir'}."/crl/crl.pem") {
      $main->print_warning("Generating CRL failed");
      _rm_dir($self->{$name}->{'dir'});
      delete($self->{$name});
      return;
   }

   # seems to be done
   push(@{$self->{'calist'}}, $name);
   @{$self->{'calist'}} = sort(@{$self->{'calist'}});
   $t = sprintf(gettext("CA: %s created"), $name);
   $main->print_info($t);

   $self->open_ca($main, $opts);
   return;
}

#
# export ca certificate chain
#
sub export_ca_chain {
   my ($self, $main, $opts, $box) = @_;
    
   my($ca, $chainfile, $parsed, $out, $t);

   $box->destroy() if(defined($box));

   $ca = $self->{'actca'};

   if(not defined($opts)) {
      $opts->{'format'}  = 'PEM';
      $opts->{'outfile'} = "/tmp/$ca-cachain.pem";
      $main->show_ca_chain_export_dialog($opts);
      return;
   }

   $chainfile = $self->{$ca}->{'dir'}."/cachain.pem";

   open(IN, "<$self->{$ca}->{'dir'}"."/cachain.pem") || do {
      $main->print_warning(gettext("Can't open certificate chain file: %s: %s"),
            $self->{$ca}->{'dir'}."/cachain.pem", $!);
      return;
   };

   open(OUT, ">$opts->{'outfile'}") || do {
      $main->print_warning(gettext("Can't open output file: %s: %s"), 
            $opts->{'outfile'}, $!);
      return;
   };

   print OUT while(<IN>);
   close OUT;
   
   $t = sprintf(gettext("Certificate Chain succesfully exported to: %s"), 
         $opts->{'outfile'});
   $main->print_info($t);

   return;
}

#
# export ca certificate
#
sub export_ca_cert {
   my ($self, $main, $opts, $box) = @_;
    
   my($ca, $certfile, $parsed, $out, $t);

   $box->destroy() if(defined($box));

   $ca = $self->{'actca'};

   $certfile = $self->{$ca}->{'dir'}."/cacert.pem";

   if(not defined($opts)) {
      $opts->{'format'}  = 'PEM';
      $opts->{'outfile'} = "/tmp/$ca-cacert.pem";
      $main->show_ca_export_dialog($opts);
      return;
   }

   $parsed = $main->{'CERT'}->parse_cert($main, 'CA');

   if(not defined $parsed) {
      $main->print_error(gettext("Can't read CA certificate"));
   }

   if($opts->{'format'} eq "PEM") {
      $out = $parsed->{'PEM'};
   } elsif ($opts->{'format'} eq "DER") {
      $out = $parsed->{'DER'};
   } elsif ($opts->{'format'} eq "TXT") {
      $out = $parsed->{'TEXT'};
   } else {
      $t = sprintf(gettext("Invalid Format for export_ca_cert(): %s"), 
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
   
   $t = sprintf(gettext("Certificate succesfully exported to: %s"), 
         $opts->{'outfile'});
   $main->print_info($t);

   return;
}

#
# export crl
#
sub export_crl {
   my ($self, $main, $opts, $box) = @_;
    
   my($ca, $t, $ret);

   $box->destroy() if(defined($box));

   $ca = $self->{'actca'};

   if(not defined($opts)) {
      $opts->{'outfile'} = "/tmp/$ca-crl.pem";
      $opts->{'format'}  = 'PEM';
      $opts->{'days'} = $main->{'TCONFIG'}->{'server_ca'}->{'default_crl_days'};

      $main->show_crl_export_dialog($opts);
      return;
   }

   if((not defined($opts->{'outfile'})) || ($opts->{'outfile'} eq '')) { 
      $main->show_crl_export_dialog($opts);
      $main->print_warning(gettext("Please give the output file"));
	   return;
      };

   if((not defined($opts->{'passwd'})) || ($opts->{'passwd'} eq '')) { 
      $t = gettext("Please give the CA password to create the Revocation List");
      $main->show_crl_export_dialog($opts);
      $main->print_warning($t);
      return;
   }

   if(not defined($main->{'OpenSSL'})) {
      $main->init_openssl($ca);
   }

   $ret = $main->{'OpenSSL'}->newcrl(
         $main,
         config  => $self->{$ca}->{'cnf'},
         pass    => $opts->{'passwd'},
         crldays => $opts->{'days'},
         outfile => $opts->{'outfile'},
         format  => $opts->{'format'}
         );

   if($ret == 1) {
      $t = gettext("Wrong CA password given\nGenerating Revocation List failed");
      $main->print_warning($t);
      return;
   } elsif($ret == 2) {
      $t = gettext("CA Key not found\nGenerating Revocation List failed");
      $main->print_warning($t);
      return;
   } elsif($ret) {
      $main->print_warning(gettext("Generating Revocation List failed"));
      return;
   }

   if (not -s $opts->{'outfile'}) {
      $main->print_warning(gettext("Generating Revocation List failed"));
      return;
   }

   $t = sprintf(gettext("CRL successfully exported to: %s"), 
         $opts->{'outfile'});
   $main->print_info($t);

   return;
}

sub _rm_dir {
   my $dir = shift;

   my $dirh;

   opendir($dirh, $dir);

   while(my $f = readdir($dirh)) {
      next if $f eq '.';
      next if $f eq '..';

      if(-d $dir."/".$f) {
         _rm_dir($dir."/".$f);
      } else {
         unlink($dir."/".$f);
      }
   }
   closedir(DIR);

   rmdir($dir);
   
   return(0);
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
