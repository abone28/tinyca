# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: CA.pm,v 1.34 2004/07/23 10:46:14 sm Exp $
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

   if(not -d $self->{'init'}->{'tmpdir'}) {
      print "create temp dir: $self->{'init'}->{'tmpdir'}\n";
      mkdir($self->{'init'}->{'tmpdir'}, 0700);
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

   GUI::HELPERS::set_cursor($main, 1);

   my ($i, $cnf, @lines, $oldca, $index, $bak, $t);

   $main->{'bar'}->set_status(gettext("  Opening CA: ").$opts->{'name'});
   while(Gtk->events_pending) {
      Gtk->main_iteration;
   }

   if(!exists($self->{$opts->{'name'}})) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(gettext("Invalid CA selected"));
      return;
   }

   # selected CA is already open
   if ((defined($self->{'actca'})) && 
       ($opts->{'name'} eq $self->{'actca'})) { 
      GUI::HELPERS::set_cursor($main, 0);
      print STDERR "DEBUG: ca $opts->{'name'} already opened\n";
      return;
   }

   $self->{'actca'} = $opts->{'name'};
   $self->{'cadir'} = $self->{$opts->{'name'}}->{'dir'};
   $main->{'cadir'} = $self->{'cadir'};

   if(my $dir = HELPERS::get_export_dir($main)) {
      $main->{'exportdir'} = $dir;
   }

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

   delete($main->{'OpenSSL'}->{'CACHE'});
   delete($main->{'CERT'}->{'OpenSSL'}->{'CACHE'});
   delete($main->{'REQ'}->{'OpenSSL'}->{'CACHE'});
   delete($main->{'OpenSSL'});

   $main->{'bar'}->set_status(gettext("  Initializing OpenSSL"));
   $main->{'OpenSSL'} = OpenSSL->new($main->{'init'}->{'opensslbin'},
                                     $main->{'tmpdir'});

   $index = $self->{'cadir'}."/index.txt";

   $main->{'bar'}->set_status(gettext("  Check for CA Version"));
   while(Gtk->events_pending) {
      Gtk->main_iteration;
   }

   open(INDEX, "+<$index") || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_error(gettext("Can't open index file: ".$!));
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
      while(Gtk->events_pending) {
         Gtk->main_iteration;
      }
      $self->{'actca'} = undef;
      GUI::HELPERS::set_cursor($main, 0);
      $main->show_ca_convert_dialog($opts);
      return;
   }

   if($opts->{'doconv'}) {
      open(INDEX, "+<$index") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_error(gettext("Can't open index file: ".$!));
         return;
      };
      $bak = $index.".bak";
      open(BAK, "+>$bak") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_error(gettext("Can't open index backup: ").$!);
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

      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_info($t);
   }

   GUI::HELPERS::set_cursor($main, 1);

   $main->{'bar'}->set_status(gettext("  Read Configuration"));
   while(Gtk->events_pending) {
      Gtk->main_iteration;
   }
   $main->{'TCONFIG'}->init_config($main, $opts->{'name'});

   $main->{'bar'}->set_status(gettext("  Create GUI"));
   while(Gtk->events_pending) {
      Gtk->main_iteration;
   }
   $main->create_mframe(1);

   $main->{'bar'}->set_status(gettext("  Create Toolbar"));
   while(Gtk->events_pending) {
      Gtk->main_iteration;
   }
   $main->create_toolbar('ca');

   $main->{'nb'}->set_page(0);

   $main->{'bar'}->set_status(gettext("  Actual CA: ").$self->{'actca'});
   while(Gtk->events_pending) {
      Gtk->main_iteration;
   }

   GUI::HELPERS::set_cursor($main, 0);

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
      GUI::HELPERS::print_warning(gettext("Invalid CA selected"));
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

   GUI::HELPERS::set_cursor($main, 1);

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

   delete($main->{'reqbrowser'});
   delete($main->{'certbrowser'});

   delete($main->{'REQ'}->{'reqlist'});
   delete($main->{'CERT'}->{'certlist'});

   foreach(@{$self->{'calist'}}) {
      next if $_ eq $name;
      push(@tmp, $_);
   }
   $self->{'calist'} = \@tmp;

   delete($self->{$name});

   $main->create_mframe();

   GUI::HELPERS::set_cursor($main, 0);

   $t = sprintf(gettext("CA: %s deleted"), $name);
   GUI::HELPERS::print_info($t);

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
      $opts->{'bits'} = 4096;
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
         GUI::HELPERS::print_warning(
             gettext("Password of parent CA is needed for creating a Sub CA"));
         return;
      }
   }

   if((not defined($opts->{'name'})) || 
	   ($opts->{'name'} eq "") ||
	   ($opts->{'name'} =~ /\s/)) { 
      $main->show_ca_dialog($opts, $mode);
      GUI::HELPERS::print_warning(gettext("Name must be filled in and must")
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
      GUI::HELPERS::print_warning(gettext("Please specify at least Common Name, ")
                           .gettext("Country and Password"));
      return;
   }

   if((not defined($opts->{'passwd2'})) ||
      $opts->{'passwd'} ne $opts->{'passwd2'}) { 
      $main->show_ca_dialog($opts, $mode);
      GUI::HELPERS::print_warning(gettext("Passwords don't match"));
      return;
   }

   $opts->{'C'} = uc($opts->{'C'});

   if(length($opts->{'C'}) != 2) { 
      $main->show_ca_dialog($opts, $mode);
      GUI::HELPERS::print_warning(gettext("Country must be exact 2 letter code"));
      return;
   }

   $name = $opts->{'name'};

   $t = sprintf(gettext("CA: %s already exists"), $name);
   if(defined($self->{$name})) { 
      $main->show_ca_dialog($opts, $mode);
      GUI::HELPERS::print_warning($t);
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
      GUI::HELPERS::print_error(gettext("No CA name given"));
      return;
   }
 
   # create directories
   $self->{$name}->{'dir'} = $self->{'init'}->{'basedir'}."/".$name;

   mkdir($self->{$name}->{'dir'}, 0700) || do { 
      GUI::HELPERS::print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/req", 0700) || do { 
      GUI::HELPERS::print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/keys", 0700) || do { 
      GUI::HELPERS::print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/certs", 0700) || do { 
      GUI::HELPERS::print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/crl", 0700) || do { 
      GUI::HELPERS::print_error(gettext("Can't create directory: ").$!);
      return;
   };

   mkdir($self->{$name}->{'dir'}."/newcerts", 0700) || do { 
      GUI::HELPERS::print_error(gettext("Can't create directory: ").$!);
      return;
   };

   # create configuration file
   my $in  = $self->{'init'}->{'templatedir'}."/openssl.cnf";
   my $out = $self->{$name}->{'dir'}."/openssl.cnf";

   open(IN, "<$in") || do {
      $t = sprintf(gettext("Can't open template file %s %s"), $in, $!);
      GUI::HELPERS::print_error($t);
      return;
   };
   open(OUT, ">$out") || do {
      $t = sprintf(gettext("Can't open output file: %s: %s"),$out, $!);
      GUI::HELPERS::print_error($t);
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
      GUI::HELPERS::print_error(gettext("Can't open index file: ").$!);
      return;
   };
   close OUT;

   $serial = $self->{$name}->{'dir'}."/serial";
   open(OUT, ">$serial") || do {
      GUI::HELPERS::print_error(gettext("Can't write serial file: ").$!);
      return;
   };
   print OUT "01";
   close OUT;

   if(defined($mode) && $mode eq "sub") {
      $self->create_ca($main, $opts, undef, $mode);
   } else {
      GUI::TCONFIG::show_config_ca($main, $opts, $mode);
   }

   return;
}

#
# now create the CA certificate and CRL
#
sub create_ca {
   my ($self, $main, $opts, $box, $mode, $name) = @_;

   my ($fname, $t, $index, $serial, $ca, $ret, $ext);

   $ca = $self->{'actca'};

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);

   $name = $opts->{'name'};

   if((!defined($name)) || $name eq '') {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_error(gettext("No CA name given"));
      return;
   }

   # create CA certifikate
   ($ret, $ext) = $main->{'OpenSSL'}->newkey( 
         'bits'    => $opts->{'bits'},
         'outfile' => $self->{$name}->{'dir'}."/cacert.key",
         'pass'    => $opts->{'passwd'}
         );
   
   if (not -s $self->{$name}->{'dir'}."/cacert.key" || $ret) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(gettext("Generating key failed"), $ext);
      _rm_dir($self->{$name}->{'dir'});
      delete($self->{$name});
      return;
   }

   ($ret, $ext) = $main->{'OpenSSL'}->newreq( 
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

   $fname = HELPERS::gen_name($opts);

   $opts->{'reqname'} = MIME::Base64::encode($fname, '');
   
   if (not -s $self->{$name}->{'dir'}."/cacert.req" || $ret) {
      unlink($self->{$name}->{'dir'}."/cacert.key");
      unlink($self->{$name}->{'dir'}."/cacert.req");
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(gettext("Generating Request failed"), $ext);
      _rm_dir($self->{$name}->{'dir'});
      delete($self->{$name});
      return;
   } else {
   if(defined($mode) && $mode eq "sub") {
      # for SubCAs: copy the request to the signing CA
      open(IN, "<$self->{$name}->{'dir'}"."/cacert.req") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(gettext("Can't read Certificate"));
         return;
      };
      open(OUT, ">$self->{$ca}->{'dir'}"."/req/".$opts->{'reqname'}.".pem") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(gettext("Can't write Certificate"));
         return;
      };
      print OUT while(<IN>);
      close IN; close OUT;

      # for SubCAs: copy the key to the signing CA
      open(IN, "<$self->{$name}->{'dir'}"."/cacert.key") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(gettext("Can't read Certificate"));
         return;
      };
      open(OUT, ">$self->{$ca}->{'dir'}"."/keys/".$opts->{'reqname'}.".pem") || do {
         GUI::HELPERS::set_cursor($main, 0);
         GUI::HELPERS::print_warning(gettext("Can't write Certificate"));
         return;
      };
      print OUT while(<IN>);
      close IN; close OUT;
    }
   }

   if(defined($mode) && $mode eq "sub") {
      ($ret, $ext) = $main->{'REQ'}->sign_req(
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
      ($ret, $ext) = $main->{'OpenSSL'}->newcert( 
            'config'  => $self->{$name}->{'cnf'},
            'outfile' => $self->{$name}->{'dir'}."/cacert.pem",
            'keyfile' => $self->{$name}->{'dir'}."/cacert.key",
            'reqfile' => $self->{$name}->{'dir'}."/cacert.req",
            'digest'  => $opts->{'digest'},
            'pass'    => $opts->{'passwd'},
            'days'    => $opts->{'days'}
            );
   }
   
   if (not -s $self->{$name}->{'dir'}."/cacert.pem" || $ret) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(
            gettext("Generating certificate failed"), $ext);
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
        GUI::HELPERS::set_cursor($main, 0);
        GUI::HELPERS::print_warning($t);
        _rm_dir($self->{$name}->{'dir'});
        delete($self->{$name});
        return;
     };
     open(OUT, ">$out") || do {
        $t = sprintf(gettext("Can't create certificate chain file: %s: %s"),$out, $!);
        GUI::HELPERS::set_cursor($main, 0);
        $main->print_warning($t);
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
        GUI::HELPERS::set_cursor($main, 0);
        GUI::HELPERS::print_warning($t);
        _rm_dir($self->{$name}->{'dir'});
        delete($self->{$name});
        return;
     };

     while(<IN>) {
        print OUT;
     }
     close OUT;
   }

   ($ret, $ext) = $main->{'OpenSSL'}->newcrl(
         config  => $self->{$name}->{'cnf'},
         pass    => $opts->{'passwd'},
         crldays => $main->{'TCONFIG'}->{'server_ca'}->{'default_crl_days'},
         outfile => $self->{$name}->{'dir'}."/crl/crl.pem",
         format  => 'PEM'
         );

   if (not -s $self->{$name}->{'dir'}."/crl/crl.pem" || $ret) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(gettext("Generating CRL failed"), $ext);
      _rm_dir($self->{$name}->{'dir'});
      delete($self->{$name});
      return;
   }

   # seems to be done
   push(@{$self->{'calist'}}, $name);
   @{$self->{'calist'}} = sort(@{$self->{'calist'}});
   $t = sprintf(gettext("CA: %s created"), $name);
   GUI::HELPERS::set_cursor($main, 0);

   GUI::HELPERS::print_info($t);

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
      $opts->{'outfile'} = "$main->{'exportdir'}/$ca-cachain.pem";
      $main->show_ca_chain_export_dialog($opts);
      return;
   }

   GUI::HELPERS::set_cursor($main, 1);

   $chainfile = $self->{$ca}->{'dir'}."/cachain.pem";

   open(IN, "<$self->{$ca}->{'dir'}"."/cachain.pem") || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(
            gettext("Can't open certificate chain file: %s: %s"),
            $self->{$ca}->{'dir'}."/cachain.pem", $!);
      return;
   };

   open(OUT, ">$opts->{'outfile'}") || do {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning(
            gettext("Can't open output file: %s: %s"), 
            $opts->{'outfile'}, $!);
      return;
   };

   print OUT while(<IN>);
   close OUT;

   $main->{'exportdir'} = HELPERS::write_export_dir($main, 
         $opts->{'outfile'});
   
   GUI::HELPERS::set_cursor($main, 0);

   $t = sprintf(gettext("Certificate Chain succesfully exported to: %s"), 
         $opts->{'outfile'});
   GUI::HELPERS::print_info($t);

   return;
}

#
# export ca certificate
#
sub export_ca_cert {
   my ($self, $main, $opts, $box) = @_;
    
   my($ca, $certfile, $parsed, $out, $t);

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);

   $ca = $self->{'actca'};

   $certfile = $self->{$ca}->{'dir'}."/cacert.pem";

   if(not defined($opts)) {
      $opts->{'format'}  = 'PEM';
      $opts->{'outfile'} = "$main->{'exportdir'}/$ca-cacert.pem";
      GUI::HELPERS::set_cursor($main, 0);
      $main->show_ca_export_dialog($opts);
      return;
   }

   $parsed = $main->{'CERT'}->parse_cert($main, 'CA');

   if(not defined $parsed) {
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_error(gettext("Can't read CA certificate"));
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
      GUI::HELPERS::set_cursor($main, 0);
      GUI::HELPERS::print_warning($t);
      return;
   }

   open(OUT, ">$opts->{'outfile'}") || do {
      GUI::HELPERS::set_cursor($main, 0);
      $t = sprintf(gettext("Can't open output file: %s: %s"), 
            $opts->{'outfile'}, $!);
      GUI::HELPERS::print_warning($t);
      return;
   };

   print OUT $out;
   close OUT;

   $main->{'exportdir'} = HELPERS::write_export_dir($main, 
         $opts->{'outfile'});
   
   GUI::HELPERS::set_cursor($main, 0);
   $t = sprintf(gettext("Certificate succesfully exported to: %s"), 
         $opts->{'outfile'});
   GUI::HELPERS::print_info($t);

   return;
}

#
# export crl
#
sub export_crl {
   my ($self, $main, $opts, $box) = @_;
    
   my($ca, $t, $ret, $ext);

   $box->destroy() if(defined($box));

   GUI::HELPERS::set_cursor($main, 1);

   $ca = $self->{'actca'};

   if(not defined($opts)) {
      $opts->{'outfile'} = "$main->{'exportdir'}/$ca-crl.pem";
      $opts->{'format'}  = 'PEM';
      $opts->{'days'} = $main->{'TCONFIG'}->{'server_ca'}->{'default_crl_days'};

      GUI::HELPERS::set_cursor($main, 0);
      $main->show_crl_export_dialog($opts);
      return;
   }

   if((not defined($opts->{'outfile'})) || ($opts->{'outfile'} eq '')) { 
      GUI::HELPERS::set_cursor($main, 0);
      $t = gettext("Please give the output file");
      $main->show_crl_export_dialog($opts);
      GUI::HELPERS::print_warning($t);
	   return;
      };

   if((not defined($opts->{'passwd'})) || ($opts->{'passwd'} eq '')) { 
      GUI::HELPERS::set_cursor($main, 0);
      $t = gettext("Please give the CA password to create the Revocation List");
      $main->show_crl_export_dialog($opts);
      GUI::HELPERS::print_warning($t);
      return;
   }

   if(not defined($main->{'OpenSSL'})) {
      $main->init_openssl($ca);
   }

   ($ret, $ext) = $main->{'OpenSSL'}->newcrl(
         config  => $self->{$ca}->{'cnf'},
         pass    => $opts->{'passwd'},
         crldays => $opts->{'days'},
         outfile => $opts->{'outfile'},
         format  => $opts->{'format'}
         );

   GUI::HELPERS::set_cursor($main, 0);

   if($ret eq 1) {
      $t = gettext("Wrong CA password given\nGenerating Revocation List failed");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   } elsif($ret eq 2) {
      $t = gettext("CA Key not found\nGenerating Revocation List failed");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   } elsif($ret) {
      $t = gettext("Generating Revocation List failed");
      GUI::HELPERS::print_warning($t, $ext);
      return;
   }

   if (not -s $opts->{'outfile'}) {
      $t = gettext("Generating Revocation List failed");
      GUI::HELPERS::print_warning($t);
      return;
   }

   $main->{'exportdir'} = HELPERS::write_export_dir($main, 
         $opts->{'outfile'});

   $t = sprintf(gettext("CRL successfully exported to: %s"), 
         $opts->{'outfile'});
   GUI::HELPERS::print_info($t, $ext);

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

1
