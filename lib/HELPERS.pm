# Copyright (c) Olaf Gellert <og@pre-secure.de> and
#               Stephan Martin <sm@sm-zone.net>
#
# $Id: HELPERS.pm,v 1.10 2004/07/15 09:01:05 sm Exp $
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
package HELPERS;

#use Gtk;
#use Gnome;

use POSIX;
use Locale::gettext;

my $version = "0.1";
my $true = 1;
my $false = undef;

# 
# generate filename from Subject-DN
# 
sub gen_name {
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

#
# generate temporary filename
#
sub mktmp { 
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


#
# finished...
#
sub exit_clean {
   my ($ret) = @_;

   $ret = 0 unless(defined $ret);
   
   # hack to avoid busy cursor
   my $rootwin = Gtk::Gdk->ROOT_PARENT();
   my $cursor  = Gtk::Gdk::Cursor->new(68);

   $rootwin->set_cursor($cursor);
   
   Gtk->exit($ret);

   exit($ret);
}

#
# split Subject DN and return hash
#
sub parse_dn {
   my $dn = shift;

   my (@dn, $k, $v, $tmp);

   $tmp = {};

   $dn =~ s/,/\//g;

   @dn = split(/\//, $dn);
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
      
   return($tmp);
}

#
# parse (requested) X509 extensions and return hash
#
sub parse_extensions {
   my ($lines, $mode) = @_;

   my ($sep, $i, $k, $v, $tmp);

   $sep = $mode eq "req"?"Requested extensions:":"X509v3 extensions:";

   $tmp = {};

   # skip everything before the extensions
   for($i = 0; defined($lines->[$i]) && $lines->[$i] !~ /^[\s\t]*$sep$/i; $i++) {
      return(undef) if not defined($lines->[$i]);
   }
   $i++;

   while($i < @{$lines}) {
      if(($lines->[$i] =~ /^[\s\t]*[^:]+:\s*$/) ||
            ($lines->[$i] =~ /^[\s\t]*[^:]+:\s+.+$/)) {
         if($lines->[$i] =~ /^[\s\t]*Signature Algorithm/i) {
            $i++;
            next;
         }
         $k = $lines->[$i];
         $k =~ s/[\s\t:]*$//g;
         $k =~ s/^[\s\t]*//g;
         $tmp->{$k} = [];
         $i++;
         while(($lines->[$i] !~ /^[\s\t].+:\s*$/) &&
               ($lines->[$i] !~ /^[\s\t]*[^:]+:\s+.+$/) &&
               ($lines->[$i] !~ /^[\s\t]*Signature Algorithm/i) &&
               ($i < @{$lines})) {
            $v = $lines->[$i];
            $v =~ s/^[\s]+//g;
            $v =~ s/[\s]+$//g;
            $i++;
            next if $v =~ /^$/;
            next if $v =~ /Signature Algorithm:/;
            my @vs = split(/,/, $v);
            foreach(@vs) {
               $_ =~ s/^\s//;
               $_ =~ s/\s$//;
               push(@{$tmp->{$k}}, $_);
            }
         }
      } else {
         $i++;
      }
   }

   return($tmp);
}

#
# get last used export directory
#
sub get_export_dir {
   my $main = shift;

   open(EXPIN, "<$main->{'cadir'}/.exportdir") || return(undef);
   my $dir = <EXPIN>;
   chomp($dir);

   return($dir);
}

#
# write last used export directory
#
sub write_export_dir {
   my ($main, $dir) = @_;

   $dir =~ s:/[^/]+$::;

   open(EXPOUT, ">$main->{'cadir'}/.exportdir") || do {
      my $t = sprintf(gettext("Can't write exportdir: %s, %s"), 
               "$main->{'cadir'}/.exportdir", $!);
      GUI::HELPERS::print_warning($t);
      return;
   };
   print EXPOUT "$dir\n";

   close(EXPOUT);

   return($dir);
}

1

__END__

=head1 NAME

HELPERS - helper functions for TinyCA, doing small jobs not related to the GUI

=head1 SYNOPSIS

   use HELPERS;

   $name    = HELPERS::gen_name($opts);
   $tmpnam  = HELPERS::mktmp($base);
   $dnhash  = HELPERS::parse_dn($dnstring);
   $exthash = HELPERS::parse_extensions($mode, $lines);
   
   exit_clean($retcode);

=head1 DESCRIPTION

HELPERS.pm is just a library, containing some useful functions used by other
TinyCA modules.

=head1 FUNCTIONS

=head2 HELPERS::gen_name($opts)

=over 1

returns a string with the TinyCA filename for a certificate, request or key.
The filename is generated from the following parts of the Subject DN from the
related request or certificate if present:

   CN EMAIL OU O L ST C

These parts need to be elements in the given options hash.

=back

=head2 HELPERS::mktmp($base)

=over 1

returns a string, containing a uniqe filename starting with $base, which is
not existing yet.

$base needs to be an absolute path to allow HELPERS::mktmp() reliable check
that the filename is really uniqe.

=back

=head2 HELPERS::parse_dn($dnstring)

=over 1

returns the reference to a hash containing all elements of the Subject DN,
given in $dnstring.

The element OU is included as an array refernce in the hash, with an array
containing all values of OU.

=back

=head2 HELPERS::parse_extensions($mode, $lines)

=over 1

returns the reference to a hash containing all X509 extensions of the given
request or certificate.

The request or certificate is given in textform as an array reference
with the array containing one line per element.

$mode contains one of the strings "req" or "cert" depending on the type of the
data.

=back

=head2 HELPERS::exit_clean($retcode)

=over 1

does nothing yet, than closing the Gtk application returning the exitcode
given in $retcode.

=back

=cut

#
# $Log: HELPERS.pm,v $
# Revision 1.10  2004/07/15 09:01:05  sm
# added hack to avoid busy cursor after exit
#
# Revision 1.9  2004/07/08 20:18:21  sm
# remeber last used export directory
#
# Revision 1.8  2004/07/08 14:28:06  sm
# store export path in file
#
# Revision 1.7  2004/06/16 07:21:11  sm
# avoid warning cause undefined var
#
# Revision 1.6  2004/06/08 17:05:47  sm
# added perldoc documentation
#
# Revision 1.5  2004/06/08 16:23:30  sm
# extracted parse_extensions() to HELPERS.pm
#
# Revision 1.4  2004/06/08 14:09:18  sm
# extracted parse_dn() to HELPERS.pm
#
# Revision 1.3  2004/05/26 12:22:02  sm
# added Log
#
#
