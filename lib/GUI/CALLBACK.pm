# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: CALLBACK.pm,v 1.2 2004/07/09 10:00:08 sm Exp $
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
package GUI::CALLBACK;

use POSIX;
use Locale::gettext;

#
# fill given var-reference with text from entry
#
sub entry_to_var {
   my ($widget, $entry, $var, $box, $words) = @_;

   if(defined($words)) {
      $$var = $words->{$entry->get_text()};
   }else{
      $$var = $entry->get_text();
   }

   $box->set_modified(1) if(defined($box));

   return;
}

#
# fill given var-reference with text from entry
# and set senitivity of togglebuttons
#
sub entry_to_var_san {
   my ($widget, $entry, $var, $box, $words, $radio1, $radio2, $radio3) = @_;

   if(defined($words)) {
      if(my $tmp = $words->{$entry->get_text()}) {
         $$var = $tmp;
      } else {
         $$var = $entry->get_text();
      }
      if(($$var ne '') && ($$var ne 'none')) {
         $radio1->set_sensitive(1) if(defined($radio1));
         $radio2->set_sensitive(1) if(defined($radio2));
         $radio3->set_sensitive(1) if(defined($radio3));
#       }elsif($$var eq 'sig'|| $$var eq 'key' || $$var eq 'keysig' ||
#              $$var eq 'keyCertSign' || $$var eq 'cRLSign' ||
#              $$var eq 'keyCertSign, cRLSign') {
#          $radio1->set_sensitive(1) if(defined($radio1));
#          $radio2->set_sensitive(1) if(defined($radio2));
#          $radio3->set_sensitive(1) if(defined($radio3));
      }else{
         $radio1->set_sensitive(0) if(defined($radio1));
         $radio2->set_sensitive(0) if(defined($radio2));
         $radio3->set_sensitive(0) if(defined($radio3));
      }
   }else{
      $$var = $entry->get_text();
   }

   $box->set_modified(1) if(defined($box));

   return;
}

#
# fill given var-reference with value from togglebutton
#
sub toggle_to_var {
   my ($button, $var, $value, $outfileref, $formatref, $fileentry, $pass1,
         $pass2) = @_;

   $$var = $value if($button->active());

   if(defined($outfileref) && defined($formatref)) {
      if($$outfileref =~ s/\.(pem|der|txt|p12|zip)$//i) {
         $$outfileref .= "." . lc $$formatref;
         $fileentry->gnome_entry->entry->set_text($$outfileref);
      }
   }
   if(defined($pass1) && defined($pass2)) {
      if($$formatref eq "PEM") {
         $pass1->set_sensitive(1);
         $pass2->set_sensitive(1);
      } elsif ($$formatref eq "DER") {
         $pass1->set_sensitive(0);
         $pass2->set_sensitive(0);
      } elsif ($$formatref eq "P12") {
         $pass1->set_sensitive(0);
         $pass2->set_sensitive(0);
      } elsif ($$formatref eq "ZIP") {
         $pass1->set_sensitive(0);
         $pass2->set_sensitive(0);
      }
   }
   return;
}

#
# fill given var-reference with value from togglebutton
#
sub toggle_to_var_pref {
   my ($button, $var, $value, $box) = @_;

   $$var = $value if($button->active());

   if(defined($box) && defined($box->notebook->cur_page())) {
      $box->set_modified(1);
   }

   return;
}

1

# 
# $Log: CALLBACK.pm,v $
# Revision 1.2  2004/07/09 10:00:08  sm
# added configuration for extendedKyUsage
#
# Revision 1.1  2004/05/23 18:27:13  sm
# initial checkin
# structural changes
#
#
