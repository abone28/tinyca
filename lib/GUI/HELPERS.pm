# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: HELPERS.pm,v 1.10 2004/06/09 13:48:29 sm Exp $
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
package GUI::HELPERS;

use POSIX;
use Locale::gettext;

#
#  Error message box, kills application
#
sub print_error {
   my ($t, $ext) = @_;
   
   my ($box, $button, $dbutton, $actionarea);

   $box = Gnome::MessageBox->new($t, 'error');
   $box->close_hides(0);
   $box->set_close(1);
   $box->set_position('mouse' );
   $box->set_policy(0, 0, 0);
   $box->set_modal(1);
   $box->realize();

   $button = Gnome::Stock->button('Button_Ok');
   $button->signal_connect('clicked', sub { HELPERS::exit_clean(1) });
   $button->can_default(1);

   $actionarea = Gtk::HButtonBox->new();
   $box->vbox->add($actionarea);
   $actionarea->pack_start($button, 1, 1, 0);
   $actionarea->set_layout('end');

   if(defined($ext)) {
      $dbutton = Gtk::Button->new_with_label(gettext("Details"));
      $box->{'shown'}      = 0;
      $box->{'actionarea'} = $actionarea;
      $box->{'dbutton'}    = $dbutton;
      $dbutton->signal_connect('clicked', 
            sub { GUI::HELPERS::toggle_textfield( $box, $ext) });
      $dbutton->can_default(1);
      $actionarea->pack_start($dbutton, 1, 1, 0);
      $actionarea->set_layout('spread');
   }

   $actionarea->set_spacing(6);
   $actionarea->set_child_ipadding(7, 0);

   $button->grab_default();

   $box->show_all();
}

#
#  Warning message box
#
sub print_warning {
   my ($t, $ext) = @_;

   my ($box, $button, $dbutton, $actionarea);

   $box = Gnome::MessageBox->new($t, 'warning');
   $box->close_hides(0);
   $box->set_close(1);
   $box->set_position('mouse' );
   $box->set_policy(0, 1, 0);
   $box->set_default_size(440, 0);
   $box->set_modal(1);
   $box->realize();

   $button = Gnome::Stock->button('Button_Ok');
   $button->signal_connect('clicked', sub { $box->destroy() });
   $button->can_default(1);

   $actionarea = Gtk::HButtonBox->new();
   $box->vbox->add($actionarea);
   $actionarea->pack_start($button, 1, 1, 0);
   $actionarea->set_layout('end');

   if(defined($ext)) {
      $dbutton = Gtk::Button->new_with_label(gettext("Details"));
      $box->{'shown'}      = 0;
      $box->{'actionarea'} = $actionarea;
      $box->{'dbutton'}    = $dbutton;
      $dbutton->signal_connect('clicked', 
            sub { GUI::HELPERS::toggle_textfield( $box, $ext) });
      $dbutton->can_default(1);
      $actionarea->pack_start($dbutton, 1, 1, 0);
      $actionarea->set_layout('spread');
   }

   $actionarea->set_spacing(6);
   $actionarea->set_child_ipadding(7, 0);

   $button->grab_default();

   $box->show_all();

   return;
}

#
#  Info message box
#
sub print_info {
   my ($t, $ext) = @_;

   my ($box, $button, $dbutton, $actionarea);

   $box = Gnome::MessageBox->new($t, 'info');
   $box->close_hides(0);
   $box->set_close(1);
   $box->set_position('mouse' );
   $box->set_policy(0, 1, 0);
   $box->set_default_size(440, 0);
   $box->set_modal(1);
   $box->realize();

   $button = Gnome::Stock->button('Button_Ok');
   $button->signal_connect('clicked', sub { $box->destroy() });
   $button->can_default(1);

   $actionarea = Gtk::HButtonBox->new();
   $box->vbox->add($actionarea);
   $actionarea->pack_start($button, 1, 1, 0);
   $actionarea->set_layout('end');

   if(defined($ext)) {
      $dbutton = Gtk::Button->new_with_label(gettext("Details"));
      $box->{'shown'}      = 0;
      $box->{'actionarea'} = $actionarea;
      $box->{'dbutton'}    = $dbutton;
      $dbutton->signal_connect('clicked', 
            sub { GUI::HELPERS::toggle_textfield( $box, $ext) });
      $dbutton->can_default(1);
      $actionarea->pack_start($dbutton, 1, 1, 0);
      $actionarea->set_layout('spread');
   }

   $actionarea->set_spacing(6);
   $actionarea->set_child_ipadding(7, 0);

   $button->grab_default();

   $box->show_all();

   return;
}

#
# create standard dialog box
#
sub dialog_box {
   my ($title, $text, $button1, $button2) = @_;

   my $box = Gnome::Dialog->new($title);
   $box->close_hides(0);
   $box->set_close(0);
   $box->set_position('center');
   $box->set_policy(0, 1, 0);
   $box->set_modal(0);

   $box->action_area->set_layout('end');
   $box->action_area->set_spacing(6);
   $box->action_area->set_child_ipadding(7, 0);
   $box->action_area->pack_start($button1, 1, 1, 0);

   if(defined($button2)) {
      $box->action_area->set_layout('spread');
      $box->action_area->pack_start($button2, 1, 1, 0);
   }

   if(defined($text)) {
      my $label = create_label($text, 'center', 0, 1);
      $box->vbox->pack_start($label, 0, 0, 0);
   }

   return($box);
}

#
# create standard label 
#
sub create_label {
   my ($text, $mode, $wrap, $bold) = @_;

   my $label = Gtk::Label->new($text);
   $label->set_justify($mode);
   if($mode eq 'center') {
      $label->set_alignment(0.5, 0.5);
   }elsif($mode eq 'left') {
      $label->set_alignment(0, 0);
   }elsif($mode eq 'right') {
      $label->set_alignment(1, 1);
   }
   $label->set_line_wrap($wrap);
   if($bold) {
      my $font    = Gtk::Gdk::Font->fontset_load(
            "-adobe-helvetica-bold-r-normal--*-120-*-*-*-*-*-*"
            );  
      if(defined($font)) {
         my $stylebold = Gtk::Style->new();
         $stylebold->font($font);
         $label->set_style($stylebold);
      }
   }
   
   return($label);
}

#
# write two labels to table
#
sub label_to_table {
   my ($key, $val, $table, $row, $mode, $wrap, $bold) = @_;

   my ($label, $entry);

   $label = create_label($key, $mode, $wrap, $bold);
   $label->set_padding(20, 0);
   $table->attach_defaults($label, 0, 1, $row, $row+1);

   $label = create_label($val, $mode, $wrap, $bold);
   $label->set_padding(20, 0);
   $table->attach_defaults($label, 1, 2, $row, $row+1);

   $row++;
   $table->resize($row, 2);

   return($row);
}

#
# write label and entry to table
#
sub entry_to_table {
   my ($text, $var, $table, $row, $visibility, $box) = @_;

   my ($label, $entry);

   $label = create_label($text, 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $row, $row+1);

   $entry = Gtk::Entry->new();
   $entry->set_text($$var) if(defined($$var));
   $table->attach_defaults($entry, 1, 2, $row, $row+1);
   $entry->signal_connect('changed', 
         \&GUI::CALLBACK::entry_to_var, $entry, $var, $box);
   $entry->set_visibility($visibility);

   return($entry);
}

#
# sort the table by the clicked column
#
sub sort_clist {
   my ($clist, $col) = @_;

   $clist->set_sort_column($col);
   $clist->sort();

   return(1);
}

#
# add/remove textfield with errormessages to dialog
#
sub toggle_textfield {
   my ($box, $ext) = @_;

   my ($scrolled, $text);
   
   if(not $box->{'shown'}) {
      $scrolled = Gtk::ScrolledWindow->new(undef, undef);
      $scrolled->set_policy('automatic', 'automatic');
      $box->vbox->add($scrolled);

      $text = Gtk::Text->new();
      $text->set_editable(0);
      $text->set_word_wrap(0);
      $text->set_line_wrap(1);

      $text->insert(undef, undef, undef, $ext);

      $scrolled->add($text);

      $box->{'shown'}    = 1;
      $box->{'scrolled'} = $scrolled;
   } elsif ($box->{'shown'} && defined($box->{'scrolled'})) {
      $box->{'scrolled'}->destroy();
      $box->{'scrolled'} = undef;
      $box->{'shown'}    = 0;
      $box->set_policy(1, 1, 1);
      $box->set_default_size(440, 0);
   }

   $box->show_all();

   return;
}

1

__END__

=head1 NAME

GUI::HELPERS - helper functions for TinyCA, doing small jobs related to the
GUI

=head1 SYNOPSIS

 use GUI::HELPERS; 

 GUI::HELPERS::print_info($text, $ext);
 GUI::HELPERS::print_warning($text, $ext);
 GUI::HELPERS::print_error($text, $ext);
 GUI::HELPERS::sort_clist($clist, $col);
 GUI::HELPERS::toggle_textfield($box, $ext);

 $box   = GUI::HELPERS::dialog_box(
       $title, $text, $button1, $button2);
 $label = GUI::HELPERS::create_label(
       $text, $mode, $wrap, $bold);
 $row   = GUI::HELPERS::label_to_table(
       $key, $val, $table, $row, $mode, $wrap, $bold);
 $entry = GUI::HELPERS::entry_to_table(
       $text, $var, $table, $row, $visibility, $box);

=head1 DESCRIPTION

GUI::HELPERS.pm is just a library, containing some useful functions used by
other TinyCA modules. All functions are related to the GUI.

=head2 GUI::HELPERS::print_info($text, $ext);

=over 1

creates an Gnome::MessageBox of the type info. The string given in $text is
shown as message, the (multiline) string $ext is available through the
"Details" Button.

=back

=head2 GUI::HELPERS::print_warning($text, $ext);

=over 1

is identically with GUI::HELPERS::print_warning(), only the Gnome::MessageBox
is of type warning.

=back

=head2 GUI::HELPERS::print_error($text, $ext);

=over 1

is identically with GUI::HELPERS::print_info(), only the Gnome::MessageBox
is of type error and the program will shut down after closing the message.

=back

=head2 GUI::HELPERS::sort_clist($clist, $col);

=over 1

sorts the clist with the values from the given column $col.
   
=back

=head2 GUI::HELPERS::toggle_textfield($box, $ext);

=over 1

is called by GUI::HELPERS::print_() functions to show or hide the text field
with extended messages in the messagebox. $box contains the reference to the
Gnome::MessageBox and $ext contains the (multiline) string with the extended
message.

=back

=head2 GUI::HELPERS::dialog_box($title, $text, $button1, $button2);

=over 1

returns the reference to a new window of type Gnome::Dialog. $title and
$button1 must be given.  $text and $button2 are optional arguments and can be
undef.

=back

=head2 GUI::HELPERS::create_label($text, $mode, $wrap, $bold);

=over 1

returns the reference to a new Gtk::Label. $mode can be "center", "left" or
"right". $wrap and $bold are boolean values.

=back

=head2 GUI::HELPERS::label_to_table($key, $val, $table, $row, $mode, $wrap, $bold);

=over 1

adds a new row to $table. The new row is appended at $row and has two columns:
the first will contain a label with the content of string $k, the second the
content of string $v. $mode, $wrap, $bold are the arguments for
GUI::HELPERS::create_label(), mentioned above. 
The function returns the number of the next free row in the table.

=back

=head2 GUI::HELPERS::entry_to_table($text, $var, $table, $row, $visibility, $box);

=over 1

adds a new row to $table. The new row is appended at $row and has two columns:
the first will contain a label with the content of the string $text, the
second one will contain a textentry Gtk::Entry, associated with the variable
$var. $visibility controls, if the entered text will be displayed or not
(passwords).
The function returns the reference to the new created entry.

=back

=cut
# 
# $Log: HELPERS.pm,v $
# Revision 1.10  2004/06/09 13:48:29  sm
# fixed all calls to OpenSSL containing $main
# fixed callbacks with wrong $words reference
# fixed some typos and wordings
#
# Revision 1.9  2004/06/09 09:32:32  sm
# added perldoc
#
# Revision 1.8  2004/05/26 10:28:32  sm
# added extended errormessages to every call of openssl
#
# Revision 1.7  2004/05/26 07:48:36  sm
# adapted functions once more :-)
#
# Revision 1.6  2004/05/26 07:25:47  sm
# moved print_* to GUI::HELPERS.pm
#
# Revision 1.5  2004/05/26 07:22:20  sm
# added toggle_textfield
#
# Revision 1.4  2004/05/26 07:03:40  arasca
# Moved miscellaneous functions to new module HELPERS.pm, removed
# Messages.pm and adapted the remaining modules accordingly.
#
# Revision 1.3  2004/05/25 14:44:42  sm
# added textfield to warning dialog
#
# Revision 1.2  2004/05/24 16:05:00  sm
# some more helpers
#
# Revision 1.1  2004/05/23 18:27:13  sm
# initial checkin
# structural changes
#
#
