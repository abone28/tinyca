# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: TCONFIG.pm,v 1.5 2004/06/09 13:48:29 sm Exp $
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
package GUI::TCONFIG;

use POSIX;
use Locale::gettext;

#
# main screen for configuration
#
sub show_configbox {
   my ($main, $name) = @_;

   my ($box, $nb, $vbox, $label, $table, $rows, @options, @options_ca, $entry,
         $key, $separator, $t, $combo, @combostrings);

   if(not defined($name)) {
      $name = $main->{'CA'}->{'actca'};
   }
   if(not defined($name)) {
      GUI::HELPERS::print_warning(gettext("Can't get CA name"));
      return;
   }

   $main->{'TCONFIG'}->init_config($main, $name);

   $box = Gnome::PropertyBox->new();
   $box->set_position('mouse');
   $box->set_policy(0, 0, 0);
   $box->set_modal(0);

   $box->signal_connect('apply', 
         sub { $main->{'TCONFIG'}->write_config($main, $name) });

   $t = gettext("All Settings are written unchanged to openssl.conf.\nSo please study the documentation of OpenSSL if you don't know exactly what to do.\nIf you are still unsure - keep the defaults and everything is expected to work fine.");
   $box->signal_connect('help', 
         sub { GUI::HELPERS::print_info($t) });

   $nb = $box->notebook();
   $nb->set_tab_pos('top');
   $nb->set_show_tabs(1);
   $nb->set_show_border(1);
   $nb->set_scrollable(0);

   # first page: vbox with warnings :-)
   $vbox = Gtk::VBox->new(0, 0);

   $label = GUI::HELPERS::create_label(
         gettext("OpenSSL Configuration"), 'center', 0,0);

   $nb->append_page($vbox, $label);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("OpenSSL Configuration"), 'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         gettext("Only change these options, if you really know, what you are doing!!"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         gettext("You should be aware, that some options may break some crappy software!!"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);


   $label = GUI::HELPERS::create_label(
         gettext("If you are unsure: leave the defaults untouched"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   # second page: server settings
   @options = qw(
         nsComment
         crlDistributionPoints
         authorityKeyIdentifier
         issuerAltName
         nsBaseUrl
         nsCaPolicyUrl
         );

   my @special_options = qw(
         nsCertType
         nsSslServerName
         nsRevocationUrl
         nsRenewalUrl
         subjectAltName
         keyUsage
         );

   @options_ca = qw(
         default_days
         );
   $vbox = Gtk::VBox->new(0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("These Settings are passed to OpenSSL for creating Server Certificates"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("Multiple Values can be separated by \",\""),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 1, 1, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(gettext("Server Certificate Settings"), 
         'center', 0, 0);
   $label = Gtk::Label->new(gettext("Server Certificate Settings"));

   $nb->append_page($vbox, $label);

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         gettext("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk::HBox->new(0, 0);
   $main->{'radio1'} = Gtk::RadioButton->new(gettext($main->{'words'}{'ip'}));
   $main->{'radio1'}->signal_connect('toggled', \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'}, 'ip', 
         $box);
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk::RadioButton->new(
         gettext($main->{'words'}{'dns'}), $main->{'radio1'});
   $main->{'radio2'}->signal_connect('toggled', \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'}, 'dns', 
         $box);
   $main->{'radiobox'}->add($main->{'radio2'});

   if($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'} 
         eq 'ip') {
      $main->{'radio1'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'} 
         eq 'dns') {
      $main->{'radio2'}->set_active(1)
   }

   $combo = Gtk::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'user'}, 
         $main->{'words'}{'emailcopy'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} 
        eq 'user') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        $combo->entry->set_text($main->{'words'}{'user'});
     }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $combo->entry->set_text($main->{'words'}{'emailcopy'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} 
        eq 'none') { 
        $combo->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', 
         \&GUI::CALLBACK::entry_to_var_san, 
         $combo->entry, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'}, 
         $box, 
         $main->{words}, 
         $main->{'radio1'},  
         $main->{'radio2'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         gettext("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk::HBox->new(0, 0);
   $main->{'radio1'} = Gtk::RadioButton->new(gettext($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled', 
         \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'}, 
         'critical', 
         $box);
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk::RadioButton->new(
         gettext($main->{'words'}{'noncritical'}), $main->{'radio1'});
   if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled', 
         \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'}, 
         'noncritical', 
         $box);
   $main->{'radiobox'}->add($main->{'radio2'});

   $combo = Gtk::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'sig'}, 
         $main->{'words'}{'key'}, 
         $main->{'words'}{'keysig'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} 
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'sig') {
           $combo->entry->set_text($main->{'words'}{'sig'});
        }elsif($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'key') {
           $combo->entry->set_text($main->{'words'}{'key'});
        }elsif($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'keysig') {
           $combo->entry->set_text($main->{'words'}{'keysig'});
        }else {
           $combo->entry->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combo->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', 
         \&GUI::CALLBACK::entry_to_var_san, 
         $combo->entry, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'}, 
         $box, 
         $main->{words}, $main->{'radio1'},  
         $main->{'radio2'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         gettext("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'server'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsCertType'})) {
      $combo->entry->set_text(
            $main->{'words'}{$main->{'TCONFIG'}->{'server_cert'}->{'nsCertType'}});
   } else {
      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', 
         \&GUI::CALLBACK::entry_to_var, 
         $combo->entry, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'nsCertType'}, 
         $box, 
         $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsSslServer
   $label = GUI::HELPERS::create_label(
         gettext("Netscape SSL Server Name (nsSslServerName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}) && 
         $main->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'} 
         eq 'user') { 
      $combo->entry->set_text($main->{'words'}{'user'});
   } else {
      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var, 
         $combo->entry, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}, 
         $box, $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRevocationUrl
   $label = GUI::HELPERS::create_label(
         gettext("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}) && 
         $main->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'} 
         eq 'user') { 
      $combo->entry->set_text($main->{'words'}{'user'});
   } else {
      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var, 
         $combo->entry, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}, 
         $box, $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRenewalUrl
   $label = GUI::HELPERS::create_label(
         gettext("Netscape Renewal URL (nsRenewalUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}) && 
         $main->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'} 
         eq 'user') { 
      $combo->entry->set_text($main->{'words'}{'user'});
   } else {
      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var, 
         $combo->entry, 
         \$main->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}, 
         $box, $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # standard options
   foreach $key (@options) { 
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'server_cert'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   foreach $key (@options_ca) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'server_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   # third page: client settings
   @options = qw(
         nsComment
         crlDistributionPoints
         authorityKeyIdentifier
         issuerAltName
         nsBaseUrl
         nsCaPolicyUrl
         );

   @options_ca = qw(
         default_days
         );
   $vbox = Gtk::VBox->new(0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("These Settings are passed to OpenSSL for creating Client Certificates"), 
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 1, 1, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(gettext("Client Certificate Settings"),
         'center', 0, 0);
   $nb->append_page($vbox, $label);

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         gettext("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk::HBox->new(0, 0);
   $main->{'radio1'} = Gtk::RadioButton->new(gettext($main->{'words'}{'ip'}));
   $main->{'radio1'}->signal_connect('toggled', 
         \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}, 'ip', 
         $box);
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk::RadioButton->new(
         gettext($main->{'words'}{'dns'}), $main->{'radio1'});
   $main->{'radio2'}->signal_connect('toggled', 
         \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}, 'dns', 
         $box);
   $main->{'radiobox'}->add($main->{'radio2'});

   $main->{'radio3'} = Gtk::RadioButton->new(
         gettext($main->{'words'}{'mail'}), $main->{'radio1'});
   $main->{'radio3'}->signal_connect('toggled', 
         \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}, 'mail', 
         $box);
   $main->{'radiobox'}->add($main->{'radio3'});

   if($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'ip') {
      $main->{'radio1'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'dns') {
      $main->{'radio2'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'mail') {
      $main->{'radio3'}->set_active(1)
   }

   $combo = Gtk::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'user'}, 
         $main->{'words'}{'emailcopy'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} 
        eq 'user') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);
        $main->{'radio3'}->set_sensitive(1);

        $combo->entry->set_text($main->{'words'}{'user'});
     }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);

        $combo->entry->set_text($main->{'words'}{'emailcopy'});
     }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} 
        eq 'none') { 
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);

        $combo->entry->set_text($main->{'words'}{'none'});
     }
   } else { 
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
      $main->{'radio3'}->set_sensitive(0);

      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var_san,
         $combo->entry, 
         \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'}, 
         $box, $main->{words}, 
         $main->{'radio1'},  $main->{'radio2'}, $main->{'radio3'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         gettext("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk::HBox->new(0, 0);
   $main->{'radio1'} = Gtk::RadioButton->new(
         gettext($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled', 
         \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'}, 'critical', 
         $box);
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk::RadioButton->new(
         gettext($main->{'words'}{'noncritical'}), $main->{'radio1'});
   if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled', 
         \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'}, 'noncritical', 
         $box);
   $main->{'radiobox'}->add($main->{'radio2'});

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'sig'}, 
         $main->{'words'}{'key'}, $main->{'words'}{'keysig'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} 
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'sig') {
           $combo->entry->set_text($main->{'words'}{'sig'});
        }elsif($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'key') {
           $combo->entry->set_text($main->{'words'}{'key'});
        }elsif($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'keysig') {
           $combo->entry->set_text($main->{'words'}{'keysig'});
        }else {
           $combo->entry->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combo->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var_san, 
         $combo->entry, \$main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'}, 
         $box, $main->{words}, $main->{'radio1'},  $main->{'radio2'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         gettext("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = (
         $main->{'words'}{'none'}, 
         $main->{'words'}{'objsign'}, 
         $main->{'words'}{'email'}, 
         $main->{'words'}{'client'}, 
         $main->{'words'}{'client, email'}, 
         $main->{'words'}{'client, objsign'},
         $main->{'words'}{'client, email, objsign'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'nsCertType'})) {
      $combo->entry->set_text( 
            $main->{'words'}{$main->{'TCONFIG'}->{'client_cert'}->{'nsCertType'}});
   } else {
      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var, 
         $combo->entry, \$main->{'TCONFIG'}->{'client_cert'}->{'nsCertType'}, 
         $box, $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRevocationUrl
   $label = GUI::HELPERS::create_label(
         gettext("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}) && 
         $main->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'} 
         eq 'user') { 
      $combo->entry->set_text($main->{'words'}{'user'});
   } else {
      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var, 
         $combo->entry, 
         \$main->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}, 
         $box, $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRenewalUrl
   $label = GUI::HELPERS::create_label(
         gettext("Netscape Renewal URL (nsRenewalUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}) && 
         $main->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'} 
         eq 'user') { 
      $combo->entry->set_text($main->{'words'}{'user'});
   } else {
      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var, 
         $combo->entry, 
         \$main->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}, 
         $box, $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # standard options
   foreach $key (@options) { 
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'client_cert'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   foreach $key (@options_ca) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'client_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   # fourth page: ca settings
   @options = qw(
         nsComment
         crlDistributionPoints
         authorityKeyIdentifier
         issuerAltName
         nsBaseUrl
         nsCaPolicyUrl
         );

   @special_options = qw(
         nsCertType
         nsRevocationUrl
         subjectAltName
         );

   @options_ca = qw(
         default_days
         );
   $vbox = Gtk::VBox->new(0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("These Settings are passed to OpenSSL for creating CA Certificates"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("Multiple Values can be separated by \",\""),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 1, 1, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(gettext("CA Certificate Settings"), 
         'center', 0, 0);
   $label = Gtk::Label->new(gettext("CA Certificate Settings"));

   $nb->append_page($vbox, $label);

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         gettext("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'emailcopy'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $combo->entry->set_text($main->{'words'}{'emailcopy'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'} 
        eq 'none') { 
        $combo->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var_san, 
         $combo->entry, \$main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'}, 
         $box, $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         gettext("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, 
                    $main->{'words'}{'emailCA'},
                    $main->{'words'}{'sslCA'},
                    $main->{'words'}{'objCA'},
                    $main->{'words'}{'sslCA, emailCA'},
                    $main->{'words'}{'sslCA, objCA'},
                    $main->{'words'}{'emailCA, objCA'},
                    $main->{'words'}{'sslCA, emailCA, objCA'} 
                    );
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'})) {
      $combo->entry->set_text(
            $main->{'words'}{$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}});
   } else {
      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var, 
         $combo->entry, \$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}, 
         $box, $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         gettext("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $main->{'radiobox'} = Gtk::HBox->new(0, 0);
   $main->{'radio1'} = Gtk::RadioButton->new(
         gettext($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled', 
         \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'critical', 
         $box);
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk::RadioButton->new(
         gettext($main->{'words'}{'noncritical'}), $main->{'radio1'});
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled', 
         \&GUI::CALLBACK::toggle_to_var_pref, 
         \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'noncritical', 
         $box);
   $main->{'radiobox'}->add($main->{'radio2'});

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, 
                    $main->{'words'}{'keyCertSign'}, 
                    $main->{'words'}{'cRLSign'}, 
                    $main->{'words'}{'keyCertSign, cRLSign'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} 
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'keyCertSign') {
           $combo->entry->set_text($main->{'words'}{'keyCertSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'cRLSign') {
           $combo->entry->set_text($main->{'words'}{'cRLSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 
                                                 'keyCertSign, cRLSign') {
           $combo->entry->set_text($main->{'words'}{'keyCertSign, cRLSign'});
        }else {
           $combo->entry->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combo->entry->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var_san, 
         $combo->entry, \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'}, 
         $box, $main->{words}, $main->{'radio1'},  $main->{'radio2'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($main->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRevocationUrl
   $label = GUI::HELPERS::create_label(
         gettext("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'}) && 
         $main->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'} 
         eq 'user') { 
      $combo->entry->set_text($main->{'words'}{'user'});
   } else {
      $combo->entry->set_text($main->{'words'}{'none'});
   }
   $combo->entry->signal_connect('changed', \&GUI::CALLBACK::entry_to_var, 
         $combo->entry, \$main->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'}, 
         $box, $main->{words});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # standard options
   foreach $key (@options) { 
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'v3_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   foreach $key (@options_ca) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'ca_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   # fifth page: crl settings
   @options = qw(
         default_crl_days
         );

   $vbox = Gtk::VBox->new(0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("These Settings are passed to OpenSSL for creating Certificate Revocation Lists"), 
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         gettext("Revocation List Settings"), 'center', 0, 0);
   $nb->append_page($vbox, $label);

   foreach $key (@options) { 
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'server_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   $box->show_all();

   return;
}

#
# configuration for CA
#
sub show_config_ca {
   my ($main, $opts, $mode) = @_;

   my(@options, $key, $box, $button_ok, $button_cancel, $table, $label,
         $entry, $rows);

   @options = qw(
         authorityKeyIdentifier
         basicConstraints
         keyUsage
         nsCertType
         issuerAltName
         nsComment
         crlDistributionPoints
         nsCaRevocationUrl
         nsCaPolicyUrl
         nsRevocationUrl
         nsPolicyUrl
         );
   
   if(not defined($opts->{'name'})) {
      GUI::HELPERS::print_warning(gettext("Can't get CA name"));
      return;
   }

   $main->{'TCONFIG'}->init_config($main, $opts->{'name'});
   
   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { 
            $main->{'TCONFIG'}->write_config($main, $opts->{'name'});
            $opts->{'configured'} = 1;
            $main->{'CA'}->create_ca($main, $opts, $box, $mode) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         gettext("CA Configuration"), gettext("CA Configuration"), 
         $button_ok, $button_cancel);


   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         gettext("These Settings are passed to OpenSSL for creating this CA Certificate"), 
         'center', 0, 1);
   $box->vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         gettext("and the CA Certificates of every SubCA, created with this CA."),
         'center', 0, 1);
   $box->vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(
         gettext("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);
   
   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         gettext("If you are unsure: leave the defaults untouched"), 
         'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $box->vbox->add($table);

   foreach $key (@options) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'v3_ca'}->{$key}, $table, $rows-1, 1);

      $rows++;
      $table->resize($rows, 2);
   }

   $box->show_all();

   return;
}

1

# 
# $Log: TCONFIG.pm,v $
# Revision 1.5  2004/06/09 13:48:29  sm
# fixed all calls to OpenSSL containing $main
# fixed callbacks with wrong $words reference
# fixed some typos and wordings
#
# Revision 1.4  2004/06/07 13:11:28  sm
# simplifications for translations, added WORDS.pm
#
# Revision 1.3  2004/05/26 07:48:36  sm
# adapted functions once more :-)
#
# Revision 1.2  2004/05/26 07:25:47  sm
# moved print_* to GUI::HELPERS.pm
#
# Revision 1.1  2004/05/23 18:27:13  sm
# initial checkin
# structural changes
#
#
