# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: GUI.pm,v 1.54 2004/05/11 18:33:58 sm Exp $
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
package GUI;

use POSIX;
use Locale::gettext;


#
# create the main object
#
sub new {
   my $that = shift;
   my $class = ref($that) || $that;

   my $self = {};
   $self->{'init'} = shift;

   bless($self, $class);

   $self->{'version'} = '0.6.0 (beta)';

   # initialize CA object
   $self->{'CA'} = CA->new($self->{'init'});

   # initialize OpenSSL object
   $self->{'OpenSSL'} = OpenSSL->new($self);

   # initialize CERT object
   $self->{'CERT'} = CERT->new();

   # initialize KEY object
   $self->{'KEY'} = KEY->new();

   # initialize REQ object
   $self->{'REQ'} = REQ->new();

   # initialize CONFIG object
   $self->{'TCONFIG'} = TCONFIG->new();

   # initialize fonts and styles
   my $font    = Gtk::Gdk::Font->fontset_load("-adobe-helvetica-bold-r-normal--*-120-*-*-*-*-*-*");
   if(defined($font)) {
      $self->{'stylebold'} = Gtk::Style->new();
      $self->{'stylebold'}->font($font);
   } else {
      $self->{'stylebold'} = undef;
   }

   my $fontfix = Gtk::Gdk::Font->fontset_load("-adobe-courier-medium-r-normal--*-120-*-*-*-*-*-*");
   if(defined($fontfix)) {
      $self->{'stylefix'} = Gtk::Style->new();
      $self->{'stylefix'}->font($fontfix);
   } else {
      $self->{'stylefix'} = undef;
   }

   $self->{'stylered'} = Gtk::Style->new();
   $self->{'stylered'}->fg('normal', Gtk::Gdk::Color->parse_color('red'));

   $self->{'stylegreen'} = Gtk::Style->new();
   $self->{'stylegreen'}->fg('normal', Gtk::Gdk::Color->parse_color('green'));

   # initialize main window
   $self->{'mw'} = Gnome::App->new("TinyCA", 
         "Tiny CA Management $self->{'version'}");

   $self->{'mw'}->set_policy(0, 1, 0);
   $self->{'mw'}->set_default_size(740, 570);
   $self->{'mw'}->signal_connect( 'delete_event', sub { Gtk->exit(0) });
   
   $self->create_nb();
   $self->{'mw'}->set_contents($self->{'nb'});

   $self->create_menu();

   $self->create_toolbar('startup');

   $self->create_bar();

   $self;
}

#
# create/update the main frame with the notebooks
#
sub create_mframe {
   my $self = shift;

   my($parsed, $calabel, $caframe, $rows, $table, @fields, $text, @childs,
         $label, $cert_export, $cert_revoke, $cert_delete, $certlabel,
         $certlistwin, @certtitles, @keytitles, $keylabel, $keylistwin,
         $reqlistwin, @reqtitles, $reqlabel, %words);

   return if not defined($self->{'CA'}->{'actca'});
   return if $self->{'CA'}->{'actca'} eq "";
   my $ca = $self->{'CA'}->{'actca'};

   $parsed = $self->{'CERT'}->parse_cert( $self, 'CA');

   defined($parsed) || $self->print_error(
         gettext("Can't read CA certificate")
         );

   ### notebooktab for ca information
   if(not defined($self->{'cabox'})) {
      $self->{'cabox'} = Gtk::VBox->new(0, 0);
      $calabel = Gtk::Label->new(gettext("CA"));
      $self->{'nb'}->insert_page($self->{'cabox'}, $calabel, 0);
   } else {
      $self->{'nb'}->hide();
      $self->{'nb'}->remove_page(0);
      $self->{'cabox'}->destroy();
      $self->{'cabox'} = Gtk::VBox->new(0, 0);
      $calabel = Gtk::Label->new(gettext("CA"));
      $self->{'nb'}->insert_page($self->{'cabox'}, $calabel, 0);
   }

   # frame for CA informations
   $self->{'caframe'} = Gtk::Frame->new(gettext("CA Information: ").$ca);
   $self->{'caframe'}->border_width(5);
   $self->{'cabox'}->pack_start($self->{'caframe'}, 1, 1, 0);

   $self->{'catextbox'} = Gtk::VBox->new(0, 0);
   $self->{'caframe'}->add($self->{'catextbox'});

   # fingerprint in the top of caframe
   if(defined($self->{'cafingerprint'})) {
      $self->{'cafingerprint'}->destroy();
   }
   $self->{'cafingerprint'} = _create_label($self,
         gettext("Fingerprint:")." ".$parsed->{'FINGERPRINT'}, 'center', 0, 0);
   $self->{'catextbox'}->pack_start($self->{'cafingerprint'}, 0, 0, 0);

   # hbox in the bottom
   if(defined($self->{'cabottombox'})) {
      $self->{'cabottombox'}->destroy();
   }
   $self->{'cabottombox'} = Gtk::HBox->new(1, 0);
   $self->{'catextbox'}->pack_start($self->{'cabottombox'}, 0, 0, 0);

   # vbox in the bottom/left
   if(defined($self->{'caleftbox'})) {
      $self->{'caleftbox'}->destroy();
   }
   $self->{'caleftbox'} = Gtk::VBox->new(0, 0);
   $self->{'cabottombox'}->add($self->{'caleftbox'});

   # vbox in the bottom/right
   if(defined($self->{'carightbox'})) {
      $self->{'carightbox'}->destroy();
   }
   $self->{'carightbox'} = Gtk::VBox->new(0, 0);
   $self->{'cabottombox'}->add($self->{'carightbox'});

   # now fill the left vbox
   @fields = qw(CN EMAIL O OU L ST C);
   $table = _create_detail_table($self, \@fields, $parsed);
   $self->{'caleftbox'}->pack_start($table, 0, 0, 0);

   # now fill the right vbox
   @fields = qw(NOTBEFORE NOTAFTER KEYSIZE PK_ALGORITHM SIG_ALGORITHM TYPE);
   $table = _create_detail_table($self, \@fields, $parsed);
   $self->{'carightbox'}->pack_start($table, 0, 0, 0);

   $self->{'catextbox'}->show_all();
   $self->{'caframe'}->show_all();

   ### notebooktab for certificates (split info and buttons)
   @certtitles = (gettext("Common Name"),
         gettext("eMail Address"),
         gettext("Organizational Unit"),
         gettext("Organization"),
         gettext("Location"),
         gettext("State"),
         gettext("Country"), 
         gettext("Status"),
         "index");

   if(not defined($self->{'certbox'})) {
      $self->{'certbox'} = Gtk::VBox->new(0, 0);
      $certlabel = Gtk::Label->new(gettext("Certificates"));
      $self->{'nb'}->insert_page($self->{'certbox'}, $certlabel, 1);

      # pane for list (top) and cert infos (bottom)
      $self->{'certpane'} = Gtk::VPaned->new();
      $self->{'certpane'}->set_handle_size(10);
      $self->{'certpane'}->set_gutter_size(8);
      $self->{'certpane'}->set_position(250);
      $self->{'certbox'}->add($self->{'certpane'});
   
      # now the list
      $certlistwin = Gtk::ScrolledWindow->new(undef, undef);
      $certlistwin->set_policy('automatic', 'automatic');
      $self->{'certpane'}->pack1($certlistwin, 1, 1);
      
      $self->{'certlist'} = Gtk::CList->new_with_titles(@certtitles);
      $self->{'certlist'}->set_sort_column (0);
      $self->{'certlist'}->signal_connect('click_column', \&_sort_clist);

      for(my $i = 0; $i < 7; $i++) {
         $self->{'certlist'}->set_column_auto_resize ($i, 1);
      }
      $self->{'certlist'}->signal_connect('select_row', 
            \&_fill_info, $self, 'cert' );
      $self->{'certlist'}->signal_connect('button_release_event', 
            \&_show_cert_menu, $self);
      $self->{'certlist'}->set_column_visibility(8, 0);
      $certlistwin->add($self->{'certlist'});

      # add a frame for the information
      $self->{'certframe'} = Gtk::Frame->new(
            gettext("Certificate Information"));
      $self->{'certframe'}->border_width(5);
      $self->{'certpane'}->pack2($self->{'certframe'}, 0, 0);

      # and the info page
      if(defined($self->{'certtextbox'})) {
         $self->{'certtextbox'}->destroy();
      }
      $self->{'certtextbox'} = Gtk::VBox->new( 0, 0 );
      $self->{'certframe'}->add($self->{'certtextbox'});

      # create popup menu
      _create_cert_menu($self);

   } else {
      $self->{'certlist'}->clear();
      if(defined($self->{'certtextbox'})) {
         $self->{'certtextbox'}->destroy();
      }
      $self->{'certtextbox'} = Gtk::VBox->new( 0, 0 );
      $self->{'certframe'}->add($self->{'certtextbox'});
   }

   $self->{'CERT'}->read_certlist($self);

   my $ind = 0;
   foreach my $n (@{$self->{'CERT'}->{'certlist'}}) {
      my ($name, $state) = split(/\%/, $n);
      my @line = split(/\:/, $name);
      my $row = $self->{'certlist'}->append(@line);
      $self->{'certlist'}->set_text($row, 7, $state);
      if($state eq gettext("VALID")) {
         $self->{'certlist'}->set_cell_style($row, 7, $self->{'stylegreen'});
      } else {
         $self->{'certlist'}->set_cell_style($row, 7, $self->{'stylered'});
      }
      $self->{'certlist'}->set_text($row, 8, $ind);
      $ind++;
   }
   # now select the first row to display certificate informations
   $self->{'certlist'}->select_row(0, 0);

   ### notebooktab for keys (split info and buttons)
   @keytitles = (gettext("Common Name"),
         gettext("eMail Address"),
         gettext("Organizational Unit"),
         gettext("Organization"),
         gettext("Location"),
         gettext("State"),
         gettext("Country"), 
         gettext("Type"), 
         "index");

   if(not defined($self->{'keybox'})) {
      $self->{'keybox'} = Gtk::VBox->new(0, 0);
      $keylabel = Gtk::Label->new(gettext("Keys"));
      $self->{'nb'}->insert_page($self->{'keybox'}, $keylabel, 2);
   
      # now the list
      $keylistwin = Gtk::ScrolledWindow->new(undef, undef);
      $keylistwin->set_policy('automatic', 'automatic');
      $self->{'keybox'}->add($keylistwin);
      
      $self->{'keylist'} = Gtk::CList->new_with_titles(@keytitles);
      $self->{'keylist'}->set_sort_column (0);
      $self->{'keylist'}->signal_connect('click_column', \&_sort_clist);

      for(my $i = 0; $i < 7; $i++) {
         $self->{'keylist'}->set_column_auto_resize ($i, 1);
      }
      $self->{'keylist'}->set_column_visibility(8, 0);
      $keylistwin->add($self->{'keylist'});
      $self->{'keylist'}->signal_connect('button_release_event', 
            \&_show_key_menu, $self);

      # create popup menu
      _create_key_menu($self);

   } else {
      $self->{'keylist'}->clear();
   }

   $self->{'KEY'}->read_keylist($self);

   $ind = 0;
   foreach my $n (@{$self->{'KEY'}->{'keylist'}}) {
      my ($name, $type) = split(/\%/, $n);
      my @line = split(/\:/, $name);
      my $row = $self->{'keylist'}->append(@line);
      $self->{'keylist'}->set_text($row, 7, $type);
      $self->{'keylist'}->set_text($row, 8, $ind);
      $ind++;
   }
   # now select the first row
   $self->{'keylist'}->select_row(0, 0);

   ### notebooktab for requests (split info and buttons)
   @reqtitles = (gettext("Common Name"),
         gettext("eMail Address"),
         gettext("Organizational Unit"),
         gettext("Organization"),
         gettext("Location"),
         gettext("State"),
         gettext("Country"), 
         "index");

   if(not defined($self->{'reqbox'})) {
      $self->{'reqbox'} = Gtk::VBox->new(0, 0);
      $reqlabel = Gtk::Label->new(gettext("Requests"));
      $self->{'nb'}->insert_page($self->{'reqbox'}, $reqlabel, 3);

      # pane for list (top) and request infos (bottom)
      $self->{'reqpane'} = Gtk::VPaned->new();
      $self->{'reqpane'}->set_handle_size(10);
      $self->{'reqpane'}->set_gutter_size(8);
      $self->{'reqpane'}->set_position(280);
      $self->{'reqbox'}->add($self->{'reqpane'});
   
      # now the list
      $reqlistwin = Gtk::ScrolledWindow->new(undef, undef);
      $reqlistwin->set_policy('automatic', 'automatic');
      $self->{'reqpane'}->pack1($reqlistwin, 1, 1);
      
      $self->{'reqlist'} = Gtk::CList->new_with_titles(@reqtitles);
      $self->{'reqlist'}->set_sort_column (0);
      $self->{'reqlist'}->signal_connect('click_column', \&_sort_clist);

      for(my $i = 0; $i < 6; $i++) {
         $self->{'reqlist'}->set_column_auto_resize ($i, 1);
      }
      $self->{'reqlist'}->signal_connect('select_row', 
            \&_fill_info, $self, 'req' );
      $self->{'reqlist'}->signal_connect('button_release_event', 
            \&_show_req_menu, $self);
      $self->{'reqlist'}->set_column_visibility(7, 0);
      $reqlistwin->add($self->{'reqlist'});

      # add a frame for the information
      $self->{'reqframe'} = Gtk::Frame->new(gettext("Request Information"));
      $self->{'reqframe'}->border_width(5);
      $self->{'reqpane'}->pack2($self->{'reqframe'}, 0, 0);

      # and the info page
      if(defined($self->{'reqtextbox'})) {
         $self->{'reqtextbox'}->destroy();
      }
      $self->{'reqtextbox'} = Gtk::VBox->new( 0, 0 );
      $self->{'reqframe'}->add($self->{'reqtextbox'});

      # create popup menu
      _create_req_menu($self);

   } else {
      $self->{'reqlist'}->clear();
      if(defined($self->{'reqtextbox'})) {
         $self->{'reqtextbox'}->destroy();
      }
      $self->{'reqtextbox'} = Gtk::VBox->new( 0, 0 );
      $self->{'reqframe'}->add($self->{'reqtextbox'});
   }

   $self->{'REQ'}->read_reqlist($self);

   $ind = 0;
   foreach my $n (@{$self->{'REQ'}->{'reqlist'}}) {
      my ($name, $state) = split(/\%/, $n);
      my @line = split(/\:/, $name);
      my $row = $self->{'reqlist'}->append(@line);
      $self->{'reqlist'}->set_text($row, 7, $ind);
      $ind++;
   }
   # now select the first row to display certificate informations
   $self->{'reqlist'}->select_row(0, 0);

   $self->{'nb'}->show_all();
   $self->{'nb'}->signal_connect('switch_page', \&_act_toolbar, $self);

   return;
}

#
# create empty notebook, add to main window and configure
# 
sub create_nb {
   my $self = shift;

   $self->{'nb'} = Gtk::Notebook->new();
   $self->{'nb'}->set_tab_pos('top');
   $self->{'nb'}->set_homogeneous_tabs(1);

   return;
}

#
# create the applicationbar
#
sub create_bar {
   my $self = shift;
   
   $self->{'bar'} = Gnome::AppBar->new(1,1,"user");
   $self->{'bar'}->set_status("   Watch out...");
   $self->{'mw'}->set_statusbar($self->{'bar'});

   return;
}

#
# keep toolbar in sync with notebook
#
sub _act_toolbar {
   my ($nb, $self, $page, $page_num) = @_;
   my $mode = 'startup';
   my $t;

   if ($page_num == 0) {
      $mode = 'ca';
      $t = gettext("  Actual CA: %s");
   } elsif ($page_num == 1) {
      $mode = 'cert';
      $t = gettext("  Actual CA: %s - Certificates");
   } elsif ($page_num == 2) {
      $mode = 'key';
      $t = gettext("  Actual CA: %s - Keys");
   } elsif ($page_num == 3) {
      $mode = 'req';
      $t = gettext("  Actual CA: %s - Requests");
   }

   $t = sprintf($t, $self->{'CA'}->{'actca'});

   $self->{'bar'}->set_status($t);

   $self->create_toolbar($mode);
}

#
# create the toolbar
#
sub create_toolbar {
   my ($self, $mode) = @_;

   my ($icon, $mask, $iconw, $item, @children, $c, $ca);

   $ca = $self->{'CA'}->{'actca'};
   
   if(defined($self->{'toolbar'})) {
      @children = $self->{'toolbar'}->children();
      for(my $i = 4; $i < @children; $i++) {
         $c = $children[$i];
         $c->destroy();
      }
   } else {
      $self->{'toolbar'} = Gtk::Toolbar->new('horizontal', 'both');
      $self->{'mw'}->set_toolbar($self->{'toolbar'});

      ## Buttons for all toolbars
      # Exit 
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Quit', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);
   
      $item = $self->{'toolbar'}->append_item(
            gettext("Exit"),
            gettext("Exit TinyCA"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', sub { $self->_exit_clean() });
   
      # Open
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Open', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);
   
      $item = $self->{'toolbar'}->append_item(
            gettext("Open CA"),
            gettext("Open an existing CA"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CA'}->get_open_name($self)});
   
      # New
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('New', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);
   
      $item = $self->{'toolbar'}->append_item(
            gettext("New CA"),
            gettext("Create a new CA"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CA'}->get_ca_create($self)});
   
      # Delete
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Trash', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);
   
      $item = $self->{'toolbar'}->append_item(
            gettext("Delete CA"),
            gettext("Delete an existing CA"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CA'}->get_ca_delete($self)});
   
      $self->{'toolbar'}->append_space();
   }

   
   if($mode eq 'ca') {
   
      # Create SubCA
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('New', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);
   
      $item = $self->{'toolbar'}->append_item(
            gettext("Sub CA"),
            gettext("Create a new Sub CA"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CA'}->get_ca_create($self, undef, undef, "sub")});
      
      # Export CA
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Save', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Export CA"),
            gettext("Export CA Certificate"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CA'}->export_ca_cert($self)});

      # Export CRL
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Save', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Export CRL"),
            gettext("Export Certificate Revocation List"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CA'}->export_crl($self)});
      
      if(-s $self->{'CA'}->{$ca}->{'dir'}."/cachain.pem") {
         # Export CA-Chain
         ($icon, $mask) = Gnome::Stock->pixmap_gdk('Save', 'GPixmap');
         $iconw = Gtk::Pixmap->new($icon, $mask);
   
         $item = $self->{'toolbar'}->append_item(
               gettext("Export Chain"),
               gettext("Export CA Certificate Chain"),
               'Private',
               $iconw);
         $item->signal_connect('clicked', 
               sub { $self->{'CA'}->export_ca_chain($self)});
      }
   
   } elsif($mode eq 'cert') {
      
      # View certificate extensions
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Search', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Details"),
            gettext("Show X.509 Extensions of the selected Certificate"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->show_details('cert') });

      # Show Certificate
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Search', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("View"),
            gettext("View selected Certificate"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->show_text('cert') });
      
      # Export certificate
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Save', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Export"),
            gettext("Export selected Certificate to file"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CERT'}->get_export_cert($self) });

      # Revoke certificate
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Stop', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Revoke"),
            gettext("Revoke selected Certificate"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CERT'}->get_revoke_cert($self) });

      # Renew certificate
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Refresh', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Renew"),
            gettext("Renew selected Certificate"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CERT'}->get_renew_cert($self) });

      # Delete certificate
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Trash', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      # Delete certificate
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Trash', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Delete"),
            gettext("Delete selected (revoked) Certificate"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'CERT'}->get_del_cert($self) });
      
   } elsif($mode eq 'key') {
      
      # Export key
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Save', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Export"),
            gettext("Export selected Key to file"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'KEY'}->get_export_key($self) });

      # Delete key
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Trash', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Delete"),
            gettext("Delete selected Key"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'KEY'}->get_del_key($self) });
      
   } elsif($mode eq 'req') {

      # Show Details
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Search', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Details"),
            gettext("Show Details of the selected Request"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->show_details('req') });

      # Show Request
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Search', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("View"),
            gettext("View selected Request"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->show_text('req') });
      
      # New Request
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('New', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("New"),
            gettext("Generate new Key and Certificate Request"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'REQ'}->get_req_create($self) });
      
      # Import Request
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Revert', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Import"),
            gettext("Import a Certificate Request"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'REQ'}->get_import_req($self) });

      # Sign Request
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Properties', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Server"),
            gettext("Sign Certificate Request/Create Server Certificate"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { my $opts = {};
                  $opts->{'type'} = 'server';
                  $self->{'REQ'}->get_sign_req($self, $opts) });

      # Sign Request
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Properties', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Client"),
            gettext("Sign Certificate Request/Create Client Certificate"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { my $opts = {};
                  $opts->{'type'} = 'client';
                  $self->{'REQ'}->get_sign_req($self, $opts); });

      # Delete Request
      ($icon, $mask) = Gnome::Stock->pixmap_gdk('Trash', 'GPixmap');
      $iconw = Gtk::Pixmap->new($icon, $mask);

      $item = $self->{'toolbar'}->append_item(
            gettext("Delete"),
            gettext("Delete selected Certificate Request"),
            'Private',
            $iconw);
      $item->signal_connect('clicked', 
            sub { $self->{'REQ'}->get_del_req($self) });
   }

   return;
}

#
# create the menubar
#
sub create_menu {
   my $self = shift;

    $self->{'mw'}->create_menus(
               { type    => 'subtree',
                 label   => gettext("_CA"),
                 subtree => [
                    { type        => 'item',
                      label       => gettext("_Open CA"),
                      pixmap_type => 'stock',
                      pixmap_info => 'Menu_Open',
                      callback    => sub { $self->{'CA'}->get_open_name($self) }
                    },
                    { type        => 'item',
                      label       => gettext("_New CA"),
                      pixmap_type => 'stock',
                      pixmap_info => 'Menu_New',
                      callback    => sub { $self->{'CA'}->get_ca_create($self)}
                    },
                    { type        => 'item',
                      label       => gettext("_Delete CA"),
                      pixmap_type => 'stock',
                      pixmap_info => 'Menu_Trash',
                      callback    => sub { $self->{'CA'}->get_ca_delete($self)}
                    },
                    { type => 'separator',
                    },
                    { type        => 'item',
                      label       => gettext("_Exit"),
                      pixmap_type => 'stock',
                      pixmap_info => 'Menu_Quit',
                      callback    => sub { $self->_exit_clean() }
                    },
                 ]
               },
               { type    => 'subtree',
                 label   => gettext("_Preferences"),
                 subtree => [
                    { type  => 'item',
                      label => gettext("Experts Only!!")
                    },
                    { type => 'separator'
                    },
                    { type        => 'item',
                      label       => gettext("OpenSSL _Configuration"),
                      pixmap_type => 'stock',
                      pixmap_info => 'Menu_Properties',
                      callback    => sub{ $self->{'TCONFIG'}->config_openssl($self) }
                    }
                 ]
               },
               { type    => 'subtree',
                 label   => gettext("_Help"),
                 subtree => [
                    { type     => 'item', 
                      label    => gettext("_Help"),
                      callback => sub{ $self->show_help() }
                    },
                    {type => 'item', 
                     label => gettext("_About TinyCA"),
                     pixmap_type => 'stock',
                     pixmap_info => 'Menu_About',
                     callback => sub { $self->about() }
                    }
                 ]
               }
              );

   return;
}

#
# pop-up to display request/cert as TXT
#
sub show_text {
   my ($self, $mode) = @_;

   my($parsed, $ind, $t, $box, $label, $text, $vscrollbar, $name, $button_ok,
         $status, $row, $scrolled, $ca);

   $ca = $self->{'CA'}->{'actca'};

   if($mode eq 'req') {
      $row = $self->{'reqlist'}->selection();
      $ind = $self->{'reqlist'}->get_text($row, 7);
   } elsif($mode eq 'cert') {
      $row = $self->{'certlist'}->selection();
      $ind = $self->{'certlist'}->get_text($row, 8);
   } else {
      $self->print_error(gettext("Invalid mode for show_text():")." ".$mode);
      return;
   }

   if((not defined $ind) && ($mode eq 'req')) { 
      $self->print_info(gettext("Please select a Request first"));
      return;
   }elsif((not defined $ind) && ($mode eq 'cert')) {
      $self->print_info(gettext("Please select a certificate first"));
      return;
   }

   if($mode eq 'req') {
      ($name, $status) = split(/\%/, $self->{'REQ'}->{'reqlist'}->[$ind]);
   }elsif($mode eq 'cert') {
      ($name, $status) = split(/\%/, $self->{'CERT'}->{'certlist'}->[$ind]);
   }

   $name = MIME::Base64::encode($name, '');

   if($mode eq 'req') {
      $parsed = $self->{'REQ'}->parse_req( $self, $name);
   } elsif($mode eq 'cert') {
      $parsed = $self->{'CERT'}->parse_cert( $self, $name);
   }

   defined($parsed) || $self->print_error(gettext("Can't read file"));

   $t = $mode eq 'req'?gettext("Request"):gettext("Certificate");

   $button_ok = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', sub { $box->destroy() });
   $button_ok->can_default(1);

   $box = _dialog_box($self, $t, $t, $button_ok);

   $box->set_default_size(550, 440);
   $button_ok->grab_default();

   $scrolled = Gtk::ScrolledWindow->new(undef, undef);
   $scrolled->set_policy('automatic', 'automatic');
   $box->vbox->pack_start($scrolled, 1, 1, 0);

   $text = Gtk::Text->new();
   $text->set_editable(0);
   $text->set_word_wrap(0);
   $text->set_line_wrap(0);
   if($self->{'stylefix'}) {
      $text->set_style($self->{'stylefix'});
   }
   $text->insert(undef, undef, undef, $parsed->{'TEXT'});
   $scrolled->add($text);

   $box->show_all();
   return;
}

#
# show request/certificate informations and extensions
#
sub show_details {
   my ($self, $mode) = @_;

   my($name, $status, $parsed, $row, $ind, $label, $table, 
         $box, $button_ok, $t, @fields, $ca);

   $ca   = $self->{'CA'}->{'actca'};

   if($mode eq 'req') {
      $row = $self->{'reqlist'}->selection();
      $ind = $self->{'reqlist'}->get_text($row, 7);
   } elsif($mode eq 'cert') {
      $row = $self->{'certlist'}->selection();
      $ind = $self->{'certlist'}->get_text($row, 8);
   } else {
      $self->print_error(gettext("Invalid mode for show_details():")." ".$mode);
      return;
   }

   if((not defined $ind) && ($mode eq 'req')) { 
      $self->print_info(gettext("Please select a Request first"));
      return;
   }elsif((not defined $ind) && ($mode eq 'cert')) {
      $self->print_info(gettext("Please select a certificate first"));
      return;
   }

   if($mode eq 'req') {
      ($name, $status) = split(/\%/, $self->{'REQ'}->{'reqlist'}->[$ind]);
   }elsif($mode eq 'cert') {
      ($name, $status) = split(/\%/, $self->{'CERT'}->{'certlist'}->[$ind]);
   }

   $name = MIME::Base64::encode($name, '');

   if($mode eq 'req') {
      $parsed = $self->{'REQ'}->parse_req( $self, $name);
   } elsif($mode eq 'cert') {
      $parsed = $self->{'CERT'}->parse_cert( $self, $name);
   }

   defined($parsed) || $self->print_error(gettext("Can't read file"));

   $t = $mode eq 'req'?gettext("Request Details"):gettext("Certificate Details");
   
   $button_ok = Gnome::Stock->button('Button_Ok');
   $button_ok->can_default(1);
   $button_ok->signal_connect('clicked', sub { $box->destroy() });

   $box = _dialog_box($self, $t, $t, $button_ok);

   $button_ok->grab_default();

   @fields = qw(CN EMAIL O OU L ST C NOTBEFORE NOTAFTER KEYSIZE
         PK_ALGORITHM SIG_ALGORITHM TYPE);

   $table = _create_detail_table($self, \@fields, $parsed);
   $box->vbox->add($table);

   if(not keys(%{$parsed->{'EXT'}})) {
      $box->show_all();
      return;
   }

   $t = $mode eq 'req'?gettext("Requested X.509 Extensions"):gettext("X.509v3 Extensions");
   $label = _create_label($self, $t, 'center', 0, 1);
   $box->vbox->add($label);

   $table = _create_extension_table($self, $parsed);
   $box->vbox->add($table);
   $box->show_all();
}

#
# pop-up to verify request import
#
sub show_req_import_verification {
   my ($self, $opts, $parsed) = @_;

   my($box, $button_ok, $button_cancel, $label, $rows, $table, $t, @fields);

   $button_ok = Gnome::Stock->button('Button_Ok');
   $button_ok->can_default(1);
   $button_ok->signal_connect('clicked', 
         sub { $self->{'REQ'}->import_req($self, $opts, $parsed, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Import Request"), gettext("Import Request"),
         $button_ok, $button_cancel);

   $button_ok->grab_default();


   $label = _create_label($self, 
         gettext("Do you really want to import the following Certificate Request?"),
         'center', 1, 0);
   $box->vbox->add($label);

   @fields = qw( CN EMAIL O OU L ST C TYPE NOTBEFORE NOTAFTER KEYSIZE
         PK_ALGORITHM SIG_ALGORITHM TYPE);

   $table = _create_detail_table($self, \@fields, $parsed);
   $box->vbox->add($table);

   if(not keys(%{$parsed->{'EXT'}})) {
      $box->show_all();
      return;
   }

   $label = _create_label($self, 
         gettext("Requested X.509 Extensions"), 'center', 0, 1);
   $box->vbox->add($label);

   $table = _create_extension_table($self, $parsed);
   $box->vbox->add($table);

   $box->show_all();

   return;
}

#
# get name for open/delete a CA
#
sub show_select_ca_dialog {
   my ($self, $action, $opts)= @_;

   my ($box, $button_ok, $button_cancel, $label, $scrolled, $list, 
         $item, $name, $t);

   if($action eq 'open') {
      $t = gettext("Open CA");
   }elsif($action eq 'delete') {
      $t = gettext("Delete CA");
   }else {
      $self->print_error(gettext("Invalid action given: ").$action);
      return;
   }
   
   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->can_default(1);

   $button_cancel = Gnome::Stock->button('Button_Cancel');

   $box = _dialog_box($self, $t, $t, $button_ok, $button_cancel);

   $button_ok->grab_default();

   $scrolled = Gtk::ScrolledWindow->new(undef, undef);
   $scrolled->set_policy('automatic', 'automatic' );
   $scrolled->border_width(0 );
   $scrolled->hscrollbar->set_update_policy('continuous' );
   $scrolled->vscrollbar->set_update_policy('continuous' );
   $box->vbox->add($scrolled);

   $list = Gtk::List->new();
   $scrolled->add_with_viewport($list);

   foreach(@{$self->{'CA'}->{'calist'}}) {
      next if (not defined $_ );
      $item = Gtk::ListItem->new($_);
      $item->{'name'} = $_;
      $list->append_items($item);
   }

   # activate doubleclick in the list
   $list->signal_connect('button_press_event', 
         sub { 
            if($_[1]->{'type'} eq '2button_press') {
               if(defined($list->selection)) {
                  $name = ($list->selection)[0]->{'name'};
                  if($action eq 'open') {
                     $opts->{'name'} = $name;
                     $self->{'CA'}->open_ca($self, $opts, $box);
                  }elsif($action eq 'delete') {
                     $self->{'CA'}->delete_ca($self, $name, $box);
                  }else {
                     $self->print_error(
                        gettext("Invalid action for show_select_ca_dialog(): ").$action);
                  }
               }
               return(1);
            }
            return(0);
         }
   );

   $button_ok->signal_connect('clicked', 
         sub { 
            if(defined($list->selection)) {
               $name = ($list->selection)[0]->{'name'};
               if($action eq 'open') {
                  $opts->{'name'} = $name;
                  $self->{'CA'}->open_ca($self, $opts, $box);
               }elsif($action eq 'delete') {
                  $self->{'CA'}->delete_ca($self, $name, $box);
               }else {
                  $self->print_error(
                     gettext("Invalid action for show_select_ca_dialog(): ").$action);
               }
            }
         }
   );
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });
   $button_ok->grab_default();

   $box->show_all();
}

#
# get data for creating a new request
#
sub show_req_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $reqtable, $radiobox, $key1, $key2,
         $key3, $key4, $key5, $entry, $label);

   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'REQ'}->get_req_create($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Create Request"), gettext("Create a new Certificate Request"),
         $button_ok, $button_cancel);

   # table for request data
   $reqtable = Gtk::Table->new(1, 13, 0);
   $reqtable->set_col_spacing(0, 7);
   $box->vbox->add($reqtable);

   $entry = _entry_to_table($self, gettext("Common Name (eg, your Name,"),
         \$opts->{'CN'}, $reqtable, 0, 1);
   $entry->grab_focus();

   $label = _create_label($self, gettext("your eMail Address"), 'right', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 2, 3);

   $label = _create_label($self, gettext("or the Servers Name)"), 'right', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 3, 4);

   $entry = _entry_to_table($self, gettext("eMail Address:"),
         \$opts->{'EMAIL'}, $reqtable, 4, 1);

   $entry = _entry_to_table($self, gettext("Password (protect your private Key):"),
         \$opts->{'passwd'}, $reqtable, 5, 0);

   $entry = _entry_to_table($self, gettext("Password (confirmation):"),
         \$opts->{'passwd2'}, $reqtable, 6, 0);

   $entry = _entry_to_table($self, gettext("Country Name (2 letter code):"),
         \$opts->{'C'}, $reqtable, 7, 1);

   $entry = _entry_to_table($self, gettext("State or Province Name:"),
         \$opts->{'ST'}, $reqtable, 8, 1);

   $entry = _entry_to_table($self, gettext("Locality Name (eg. city):"),
         \$opts->{'L'}, $reqtable, 9, 1);

   $entry = _entry_to_table($self, gettext("Organization Name (eg. company):"),
         \$opts->{'O'}, $reqtable, 10, 1);

   $entry = _entry_to_table($self, gettext("Organizational Unit Name (eg. section):"),
         \$opts->{'OU'}, $reqtable, 11, 1);

   $label = _create_label($self, gettext("Keylength:"), 'left', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 13, 14);

   $radiobox = Gtk::HBox->new(0, 0);
   $key1 = Gtk::RadioButton->new('1024');
   $key1->set_active(1) 
      if(defined($opts->{'bits'}) && $opts->{'bits'} == '1024');
   $key1->signal_connect('toggled', \&_toggle_to_var, \$opts->{'bits'}, 1024);
   $radiobox->add($key1);

   $key2 = Gtk::RadioButton->new('2048', $key1);
   $key2->set_active(1) 
      if(defined($opts->{'bits'}) && $opts->{'bits'} == '2048');
   $key2->signal_connect('toggled', \&_toggle_to_var, \$opts->{'bits'}, 2048);
   $radiobox->add($key2);

   $key3 = Gtk::RadioButton->new('4096', $key1);
   $key3->set_active(1) 
      if(defined($opts->{'bits'}) && $opts->{'bits'} == '4096');
   $key3->signal_connect('toggled', \&_toggle_to_var, \$opts->{'bits'}, 4096);
   $radiobox->add($key3);

   $reqtable->attach_defaults($radiobox, 1, 2, 13, 14);

   $label = _create_label($self, gettext("Digest:"), 'left', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 15, 16);

   $radiobox = Gtk::HBox->new(0, 0);
   $key1 = Gtk::RadioButton->new('MD5');
   $key1->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'md5');
   $key1->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'md5');
   $radiobox->add($key1);

   $key2 = Gtk::RadioButton->new('SHA1', $key1);
   $key2->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'sha1');
   $key2->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'sha1');
   $radiobox->add($key2);

   $key3 = Gtk::RadioButton->new('MD2', $key1);
   $key3->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'md2');
   $key3->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'md2');
   $radiobox->add($key3);

   $key4 = Gtk::RadioButton->new('MDC2', $key1);
   $key4->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'mdc2');
   $key4->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'mdc2');
   $radiobox->add($key4);

   $key5 = Gtk::RadioButton->new('MD4', $key1);
   $key5->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'md4');
   $key5->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'md4');
   $radiobox->add($key5);

   $reqtable->attach_defaults($radiobox, 1, 2, 15, 16);

   $label = _create_label($self, gettext("Algorithm:"), 'left', 0, 0);
   $reqtable->attach_defaults($label, 0, 1, 16, 17);

   $radiobox = Gtk::HBox->new(0, 0);
   $key1 = Gtk::RadioButton->new('RSA');
   $key1->set_active(1) 
      if(defined($opts->{'algo'}) && $opts->{'algo'} eq 'rsa');
   $key1->signal_connect('toggled', \&_toggle_to_var, \$opts->{'algo'}, 'rsa');
   $radiobox->add($key1);

   $key2 = Gtk::RadioButton->new('DSA', $key1);
   $key2->set_active(1) 
      if(defined($opts->{'algo'}) && $opts->{'algo'} eq 'dsa');
   $key2->signal_connect('toggled', \&_toggle_to_var, \$opts->{'algo'}, 'dsa');
   $radiobox->add($key2);

   $reqtable->attach_defaults($radiobox, 1, 2, 16, 17);

   $box->show_all();

   return;
}

#
# get data for revoking a certificate
#
sub show_cert_revoke_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $table, $entry, $t);

   $button_ok = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'CERT'}->get_revoke_cert($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Revoke Certificate"), gettext("Revoke Certificate"),
         $button_ok, $button_cancel);

   # small table for data
   $table = Gtk::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = _entry_to_table($self, gettext("CA Password:"),
         \$opts->{'passwd'}, $table, 0, 0);
   $entry->grab_focus();

   $box->show_all();
         
   return;
}

#
# get data for exporting a crl
#
sub show_crl_export_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $label, $format1, $format2,
         $format3, $table, $entry, $fileentry, $hbox);

   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'CA'}->export_crl($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Export CRL"), gettext("Export Revocation List to File"),
         $button_ok, $button_cancel);

   # small table for file selection
   $table = Gtk::Table->new(3, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $label = _create_label($self, gettext("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   $fileentry = Gnome::FileEntry->new('', gettext("Export CRL"));
   $fileentry->gnome_entry->set_max_saved(10);
   $fileentry->set_directory(0);
   $table->attach_defaults($fileentry, 1, 2, 0, 1);
   $fileentry->gnome_entry->entry->set_text($opts->{'outfile'})
      if(defined($opts->{'outfile'}));
   $fileentry->gnome_entry->entry->signal_connect(
         'changed', \&_entry_to_var,
         $fileentry->gnome_entry->entry,
         \$opts->{'outfile'});
   $fileentry->grab_focus();

   $entry = _entry_to_table($self, gettext("CA Password:"),
         \$opts->{'passwd'}, $table, 1, 0);
   $entry->grab_focus();

   $entry = _entry_to_table($self, gettext("Valid for (Days):"),
         \$opts->{'days'}, $table, 2, 1);

   $label = _create_label($self, gettext("Export Format:"), 'left', 0, 0);
   $box->vbox->add($label);

   $hbox = Gtk::HBox->new(0, 0);
   $box->vbox->add($hbox);

   $format1 = Gtk::RadioButton->new(gettext("PEM"));
   $format1->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'PEM');
   $format1->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
         'PEM', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
   $hbox->add($format1);

   $format2 = Gtk::RadioButton->new(
         gettext("DER"), $format1);
   $format2->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'DER');
   $format2->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
         'DER', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
   $hbox->add($format2);

   $format3 = Gtk::RadioButton->new(
         gettext("TXT"), $format1);
   $format3->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'TXT');
   $format3->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
         'TXT', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
   $hbox->add($format3);

   $box->show_all();

   return;
}

#
# get data for exporting a ca certificate chain
#
sub show_ca_chain_export_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $label, $format1, $format2,
         $format3, $table, $entry, $fileentry, $hbox);

   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'CA'}->export_ca_chain($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { $box->destroy() });

   $box = _dialog_box($self,
         gettext("Export CA Certificate Chain"), 
         gettext("Export CA Certificate Chain to File"),
         $button_ok, $button_cancel);

   # small table for file selection
   $table = Gtk::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $label = _create_label($self, gettext("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   $fileentry = Gnome::FileEntry->new('', 
         gettext("Export CA Certificate Chain"));
   $fileentry->gnome_entry->set_max_saved(10);
   $fileentry->set_directory(0);
   $table->attach_defaults($fileentry, 1, 2, 0, 1);
   $fileentry->gnome_entry->entry->set_text($opts->{'outfile'})
      if(defined($opts->{'outfile'}));
   $fileentry->gnome_entry->entry->signal_connect(
         'changed', \&_entry_to_var,
         $fileentry->gnome_entry->entry,
         \$opts->{'outfile'});
   $fileentry->grab_focus();

   $box->show_all();

   return;
}

#
# get data for exporting a ca certificate
#
sub show_ca_export_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $label, $format1, $format2,
         $format3, $table, $entry, $fileentry, $hbox);

   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'CA'}->export_ca_cert($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { $box->destroy() });

   $box = _dialog_box($self,
         gettext("Export CA Certificate"), 
         gettext("Export CA Certificate to File"),
         $button_ok, $button_cancel);

   # small table for file selection
   $table = Gtk::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $label = _create_label($self, gettext("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   $fileentry = Gnome::FileEntry->new('', gettext("Export CA Certificate"));
   $fileentry->gnome_entry->set_max_saved(10);
   $fileentry->set_directory(0);
   $table->attach_defaults($fileentry, 1, 2, 0, 1);
   $fileentry->gnome_entry->entry->set_text($opts->{'outfile'})
      if(defined($opts->{'outfile'}));
   $fileentry->gnome_entry->entry->signal_connect(
         'changed', \&_entry_to_var,
         $fileentry->gnome_entry->entry,
         \$opts->{'outfile'});
   $fileentry->grab_focus();

   $label = _create_label($self, gettext("Export Format:"), 'left', 0, 0);
   $box->vbox->add($label);

   $hbox = Gtk::HBox->new(0, 0);
   $box->vbox->add($hbox);

   $format1 = Gtk::RadioButton->new(gettext("PEM"));
   $format1->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'PEM');
   $format1->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
         'PEM', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
   $hbox->add($format1);

   $format2 = Gtk::RadioButton->new(
         gettext("DER"), $format1);
   $format2->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'DER');
   $format2->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
         'DER', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
   $hbox->add($format2);

   $format3 = Gtk::RadioButton->new(
         gettext("TXT"), $format1);
   $format3->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'TXT');
   $format3->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
         'TXT', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
   $hbox->add($format3);

   $box->show_all();

   return;
}

#
# get password for renewal of Certificate
#
sub show_cert_renew_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $label, $table, $entry, $radiobox,
         $key1, $key2);

   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'CERT'}->get_renew_cert($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Renew Certificate"), 
         gettext("Renew Certificate"),
         $button_ok, $button_cancel);

   $label = _create_label($self,
         gettext("The CA passphrase is needed for signing the Request"),
         'center', 1, 0);
   $box->vbox->add($label);

   # small table for data
   $table = Gtk::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = _entry_to_table($self, gettext("CA Password:"),
         \$opts->{'passwd'}, $table, 0, 0);
   $entry->grab_focus();

   $entry = _entry_to_table($self, gettext("Valid for (Days):"),
         \$opts->{'days'}, $table, 1, 1);

   $label = _create_label($self, 
         gettext("Type of Certificate:"), 'left', 1, 0);
   $box->vbox->add($label);
   
   $radiobox = Gtk::HBox->new(0, 0);
   $key1 = Gtk::RadioButton->new(gettext("Server"));
   $key1->set_active(1) 
      if(defined($opts->{'type'}) && $opts->{'type'} eq 'server');
   $key1->signal_connect('toggled',\&_toggle_to_var,\$opts->{'type'}, 'server');
   $radiobox->add($key1);

   $key2 = Gtk::RadioButton->new(gettext("Client"), $key1);
   $key2->set_active(1) 
      if(defined($opts->{'type'}) && $opts->{'type'} eq 'client');
   $key2->signal_connect('toggled',\&_toggle_to_var,\$opts->{'type'}, 'client');
   $radiobox->add($key2);

   $box->vbox->add($radiobox);

   $box->show_all();
         
   return;
}

#
# get password for exporting keys
#
sub show_key_nopasswd_dialog {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $label, $table, $entry);

   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'KEY'}->get_export_key($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Export Key without Passphrase"), 
         gettext("Export Key without Passphrase"),
         $button_ok, $button_cancel);


   $label = _create_label($self, 
         gettext("I hope you know what you\'re doing?"), 'center', 1, 0);
   $box->vbox->add($label);

   $label = _create_label($self,
         gettext("The Key Passphrase is needed for decryption of the Key"),
         'center', 1, 0);
   $box->vbox->add($label);

   # small table for data
   $table = Gtk::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = _entry_to_table($self, gettext("Password:"),
         \$opts->{'passwd'}, $table, 0, 0);
   $entry->grab_focus();

   $box->show_all();
         
   return;
}

#
# get filename for importing a request
#
sub show_req_import_dialog {
   my $self = shift;

   my $opts = {};
   my($box, $button_ok, $button_cancel, $entry, $table, $label);

   $button_ok = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'REQ'}->get_import_req($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Import Request"), gettext("Import Request from File"),
         $button_ok, $button_cancel);

   # small table for data
   $table = Gtk::Table->new(2, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $label = _create_label($self, gettext("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   $entry = Gnome::FileEntry->new('', gettext("Import Request File"));
   $entry->gnome_entry->set_max_saved(10);
   $entry->set_directory(0);
   $table->attach_defaults($entry, 1, 2, 0, 1);
   $entry->gnome_entry->entry->signal_connect(
         'changed', \&_entry_to_var,
         $entry->gnome_entry->entry,
         \$opts->{'infile'});
   $entry->grab_focus();

   $box->show_all();

   return;
}

#
# get data for exporting a certificate
#
sub show_export_dialog {
   my ($self, $opts, $mode) = @_;

   my ($box, $button_ok, $button_cancel, $label, $table, $entry, $fileentry,
         $format1, $format2, $format3, $format4, $format5, $passbox, $pass1,
         $pass2, $title, $text, $t);

   if($mode eq 'cert') {
      $title = gettext("Export Certificate");
   } elsif($mode eq 'key') {
      $title = gettext("Export Key");
   } else {
      $self->print_error(
            gettext("Invalid mode for show_export_dialog(): ").$mode);
      return;
   }
         
   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_cancel = Gnome::Stock->button('Button_Cancel');

   if($mode eq 'cert') {
      $button_ok->signal_connect('clicked', 
            sub { $self->{'CERT'}->get_export_cert($self, $opts, $box) });
   } else {
      $button_ok->signal_connect('clicked',
            sub { $self->{'KEY'}->get_export_key($self, $opts, $box) });
   }
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   if($mode eq 'cert') {
      $text = gettext("Export Certificate to File");
   } else {
      $text = gettext("Export Key to File");
   }
   
   $box = _dialog_box($self, $title, $text, $button_ok, $button_cancel);

   # small table for file selection
   $table = Gtk::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $label = _create_label($self, gettext("File:"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, 0, 1);

   if($mode eq 'cert') {
      $t = gettext("Export Certificate");
   }else {
      $t = gettext("Export Key");
   }
   
   $fileentry = Gnome::FileEntry->new('', $t);
   $fileentry->gnome_entry->set_max_saved(10);
   $fileentry->set_directory(0);
   $table->attach_defaults($fileentry, 1, 2, 0, 1);
   $fileentry->gnome_entry->entry->set_text($opts->{'outfile'})
      if(defined($opts->{'outfile'}));
   $fileentry->gnome_entry->entry->signal_connect(
         'changed', \&_entry_to_var,
         $fileentry->gnome_entry->entry,
         \$opts->{'outfile'});
   $fileentry->grab_focus();

   $label = _create_label($self, gettext("Export Format:"), 'center', 0, 0);
   $box->vbox->add($label);
   
   if($mode eq 'cert') {
      $t = gettext("PEM (Certificate)");
   }else {
      $t = gettext("PEM (Key)");
   }
   
   $format1 = Gtk::RadioButton->new($t);
   $format1->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'PEM');
   $box->vbox->add($format1);

   if($mode eq 'cert') {
      $t = gettext("DER (Certificate)");
   }else {
      $t = gettext("DER (Key without Passphrase)");
   }

   $format2 = Gtk::RadioButton->new($t, $format1);
   $format2->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'DER');
   $box->vbox->add($format2);

   $t = gettext("PKCS#12 (Certificate & Key)");

   $format3 = Gtk::RadioButton->new($t, $format1);
   $format3->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'P12');
   $box->vbox->add($format3);

   $t = gettext("Zip (Certificate & Key)");

   $format4 = Gtk::RadioButton->new($t, $format1);
   $format4->set_active(1)
      if(defined($opts->{'format'}) && $opts->{'format'} eq 'ZIP');
   $box->vbox->add($format4);
   if(not -x $self->{'init'}->{'zipbin'}) {
      $format4->set_sensitive(0);
   }

   if($mode eq 'cert') {
      $format5 = Gtk::RadioButton->new(
            gettext("TXT (Certificate)"), $format1);
      $format5->set_active(1)
         if(defined($opts->{'format'}) && $opts->{'format'} eq 'TXT');
      $box->vbox->add($format5);
   } else {
      $label = _create_label($self, 
            gettext("Without Passphrase (PEM)"), 'left', 0, 0);
      $box->vbox->add($label);

      $passbox = Gtk::HBox->new(0, 0);
      $box->vbox->add($passbox);

      $pass1 = Gtk::RadioButton->new(gettext("Yes"));
      $pass1->set_active(1)
         if(defined($opts->{'nopass'}) && $opts->{'nopass'} == 1);
      $pass1->signal_connect('toggled',
            \&_toggle_to_var, \$opts->{'nopass'}, 1);
      $passbox->add($pass1);

      $pass2 = Gtk::RadioButton->new(gettext("No"), $pass1);
      $pass2->set_active(1)
         if(defined($opts->{'nopass'}) && $opts->{'nopass'} == 0);
      $pass2->signal_connect('toggled',
            \&_toggle_to_var, \$opts->{'nopass'}, 0);
      $passbox->add($pass2);
   }

   if($mode eq 'cert') {
      $format1->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
            'PEM', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
      $format2->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
            'DER', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
      $format3->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
            'P12', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
      $format4->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
            'ZIP', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
      $format5->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
            'TXT', \$opts->{'outfile'}, \$opts->{'format'}, $fileentry);
   }else {
      $format1->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
            'PEM', \$opts->{'outfile'}, \$opts->{'format'}, 
            $fileentry, $pass1, $pass2);
      $format2->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
            'DER', \$opts->{'outfile'}, \$opts->{'format'}, 
            $fileentry, $pass1, $pass2);
      $format3->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
            'P12', \$opts->{'outfile'}, \$opts->{'format'}, 
            $fileentry, $pass1, $pass2);
      $format4->signal_connect('toggled', \&_toggle_to_var, \$opts->{'format'}, 
            'ZIP', \$opts->{'outfile'}, \$opts->{'format'}, 
            $fileentry, $pass1, $pass2);
   }

   $box->show_all();

   return;
}

#
# get export passwd for pkcs#12
#
sub show_p12_export_dialog {
   my ($self, $opts, $mode) = @_;

   my ($box, $label, $table, $entry, $button_ok, $button_cancel, $radiobox,
         $includeca1, $includeca2);

   $button_ok     = Gnome::Stock->button('Button_Ok');
   if($mode eq 'key') {
      $button_ok->signal_connect('clicked', 
         sub { $self->{'KEY'}->get_export_key($self, $opts, $box) });
   } elsif($mode eq 'cert') {
      $button_ok->signal_connect('clicked', 
         sub { $self->{'CERT'}->get_export_cert($self, $opts, $box) });
   }

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Export to PKCS#12"), gettext("Export to PKCS#12"),
         $button_ok, $button_cancel);

   # small table for storage name
   $table = Gtk::Table->new(2, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = _entry_to_table($self, gettext("Key Password:"),
         \$opts->{'passwd'}, $table, 0, 0);
   $entry->grab_focus();

   $entry = _entry_to_table($self, gettext("Export Password:"),
         \$opts->{'p12passwd'}, $table, 1, 0);

   $label = _create_label($self,
         gettext("Add CA Certificate to PKCS#12 structure"), 'left', 0, 0);
   $box->vbox->add($label);

   $radiobox = Gtk::HBox->new(0, 0);
   $box->vbox->add($radiobox);

   $includeca1 = Gtk::RadioButton->new(gettext("Yes"));
   $includeca1->set_active(1) 
      if(defined($opts->{'includeca'}) && $opts->{'includeca'} == 1);
   $includeca1->signal_connect('toggled', 
         \&_toggle_to_var, \$opts->{'includeca'}, 1);
   $radiobox->add($includeca1);

   $includeca2 = Gtk::RadioButton->new(gettext("No"), $includeca1);
   $includeca2->set_active(1) 
      if(defined($opts->{'includeca'}) && $opts->{'includeca'} == 0);
   $includeca2->signal_connect('toggled', 
         \&_toggle_to_var, \$opts->{'includeca'}, 1);
   $radiobox->add($includeca2);

   $box->show_all();

   return;
}

#
# get data for signing a request
#
sub show_req_sign_dialog {
   my ($self, $opts) = @_;

   my($box, $button_ok, $button_cancel, $entry, $table, $t, $rows);

   $rows = 0;

   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $self->{'REQ'}->get_sign_req($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Sign Request"), gettext("Sign Request/Create Certificate"), 
         $button_ok, $button_cancel);

   # small table for data
   $table = Gtk::Table->new(2, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = _entry_to_table($self, gettext("CA Password:"),
         \$opts->{'passwd'}, $table, $rows, 0);
   $rows++;
   $entry->grab_focus();


   $entry = _entry_to_table($self, gettext("Valid for (Days):"),
         \$opts->{'days'}, $table, $rows, 1);
   $rows++;

   if($opts->{'type'} eq 'server') {
      if(defined($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'}) &&
         $self->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} eq 'user') {
         if($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'} 
               eq 'ip'){
            $t = gettext("Subject alternative name (IP Address):");
         }elsif($self->{TCONFIG}->{'server_cert'}->{'subjectAltNameType'} 
               eq 'dns'){
            $t = gettext("Subject alternative name (DNS Name):");
         }
         $entry = _entry_to_table($self, $t,
               \$opts->{'subjectAltName'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}) && 
         $self->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'} eq 'user') { 
         $entry = _entry_to_table($self, gettext("Netscape SSL Server Name:"), 
               \$opts->{'nsSslServerName'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}) && 
         $self->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'} eq 'user') { 
         $entry = _entry_to_table($self, gettext("Netscape Revocation URL:"), 
               \$opts->{'nsRevocationUrl'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}) && 
         $self->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'} eq 'user') { 
         $entry = _entry_to_table($self, gettext("Netscape Renewal URL:"), 
               \$opts->{'nsRenewalUrl'}, $table, $rows, 1);
         $rows++;
      }
   }elsif($opts->{'type'} eq 'client') {
      if(defined($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'}) &&
         $self->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} eq 'user') {
         if($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
               eq 'ip'){
            $t = gettext("Subject alternative name (IP Address):");
         }elsif($self->{TCONFIG}->{'client_cert'}->{'subjectAltNameType'} 
               eq 'dns'){
            $t = gettext("Subject alternative name (DNS Name):");
         }elsif($self->{TCONFIG}->{'client_cert'}->{'subjectAltNameType'} 
               eq 'mail'){
            $t = gettext("Subject alternative name (Email):");
         }
         $entry = _entry_to_table($self, $t,
               \$opts->{'subjectAltName'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}) && 
         $self->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'} eq 'user') { 
         $entry = _entry_to_table($self, gettext("Netscape Revocation URL:"), 
               \$opts->{'nsRevocationUrl'}, $table, $rows, 1);
         $rows++;
      }
      if(defined($self->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}) && 
         $self->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'} eq 'user') { 
         $entry = _entry_to_table($self, gettext("Netscape Renewal URL:"), 
               \$opts->{'nsRenewalUrl'}, $table, $rows, 1);
         $rows++;
      }
   }

   $box->show_all();

   return;
}

#
# get data for creating a new CA
#
sub show_ca_dialog {
   my ($self, $opts, $mode) = @_;

   my ($box, $button_ok, $button_cancel, $label, $table, $entry, 
         $catable, $pwtable, $radiobox, $key1, $key2, $key3,
         $key4, $key5);

   $button_ok = Gnome::Stock->button('Button_Ok');
   $button_ok->can_default(1);

   $button_ok->signal_connect('clicked', 
      sub { $self->{'CA'}->get_ca_create($self, $opts, $box, $mode) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   if(defined($mode) && $mode eq "sub") {
      $box = _dialog_box($self,
            gettext("Create CA"), gettext("Create a new Sub CA"),
            $button_ok, $button_cancel);
   } else {
      $box = _dialog_box($self,
            gettext("Create CA"), gettext("Create a new CA"),
            $button_ok, $button_cancel);
   }


   $button_ok->grab_default();

   if(defined($mode) && $mode eq "sub") {
      # small table for ca-password
      $pwtable = Gtk::Table->new(1, 2, 0);
      $pwtable->set_col_spacing(0, 10);
      $box->vbox->add($pwtable);
   
      $entry = _entry_to_table($self, 
            gettext("CA Password (for creating the new CA):"),
            \$opts->{'parentpw'}, $pwtable, 0, 0);
      $entry->grab_focus();
   }

   # small table for storage name
   $table = Gtk::Table->new(1, 2, 0);
   $table->set_col_spacing(0, 10);
   $box->vbox->add($table);

   $entry = _entry_to_table($self, gettext("Name (for local storage):"),
         \$opts->{'name'}, $table, 0, 1);
   if(not defined($mode)) {
      $entry->grab_focus();
   }

   $label = _create_label($self, 
         gettext("Data for CA Certificate"), 'left', 0, 0);
   $box->vbox->add($label);

   # table for ca data
   $catable = Gtk::Table->new(1, 13, 0);
   $catable->set_col_spacing(0, 10);
   $box->vbox->add($catable);

   $entry = _entry_to_table($self, gettext("Common Name (for the CA):"),
         \$opts->{'CN'}, $catable, 0, 1);

   $entry = _entry_to_table($self, gettext("Country Name (2 letter code):"),
         \$opts->{'C'}, $catable, 1, 1);

   $entry = _entry_to_table($self, gettext("Password (needed for signing):"),
         \$opts->{'passwd'}, $catable, 2, 0);

   $entry = _entry_to_table($self, gettext("Password (confirmation):"),
         \$opts->{'passwd2'}, $catable, 3, 0);

   $entry = _entry_to_table($self, gettext("State or Province Name:"),
         \$opts->{'ST'}, $catable, 4, 1);

   $entry = _entry_to_table($self, gettext("Locality Name (eg. city):"),
         \$opts->{'L'}, $catable, 5, 1);

   $entry = _entry_to_table($self, gettext("Organization Name (eg. company):"),
         \$opts->{'O'}, $catable, 6, 1);

   $entry = _entry_to_table($self, gettext("Organizational Unit Name (eg. section):"),
         \$opts->{'OU'}, $catable, 7, 1);

   $entry = _entry_to_table($self, gettext("eMail Address:"),
         \$opts->{'EMAIL'}, $catable, 8, 1);

   $entry = _entry_to_table($self, gettext("Valid for (Days):"),
         \$opts->{'days'}, $catable, 9, 1);

   $label = _create_label($self, gettext("Keylength:"), 'left', 0, 0);
   $catable->attach_defaults($label, 0, 1, 10, 11);

   $radiobox = Gtk::HBox->new(0, 0);
   $key1 = Gtk::RadioButton->new('1024');
   $key1->set_active(1) 
      if(defined($opts->{'bits'}) && $opts->{'bits'} == '1024');
   $key1->signal_connect('toggled', \&_toggle_to_var, \$opts->{'bits'}, 1024);
   $radiobox->add($key1);

   $key2 = Gtk::RadioButton->new('2048', $key1);
   $key2->set_active(1) 
      if(defined($opts->{'bits'}) && $opts->{'bits'} == '2048');
   $key2->signal_connect('toggled', \&_toggle_to_var, \$opts->{'bits'}, 2048);
   $radiobox->add($key2);

   $key3 = Gtk::RadioButton->new('4096', $key1);
   $key3->set_active(1) 
      if(defined($opts->{'bits'}) && $opts->{'bits'} == '4096');
   $key3->signal_connect('toggled', \&_toggle_to_var, \$opts->{'bits'}, 4096);
   $radiobox->add($key3);

   $catable->attach_defaults($radiobox, 1, 2, 10, 11);

   $label = _create_label($self, gettext("Digest:"), 'left', 0, 0);
   $catable->attach_defaults($label, 0, 1, 15, 16);

   $radiobox = Gtk::HBox->new(0, 0);
   $key1 = Gtk::RadioButton->new('MD5');
   $key1->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'md5');
   $key1->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'md5');
   $radiobox->add($key1);

   $key2 = Gtk::RadioButton->new('SHA1', $key1);
   $key2->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'sha1');
   $key2->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'sha1');
   $radiobox->add($key2);

   $key3 = Gtk::RadioButton->new('MD2', $key1);
   $key3->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'md2');
   $key3->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'md2');
   $radiobox->add($key3);

   $key4 = Gtk::RadioButton->new('MDC2', $key1);
   $key4->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'mdc2');
   $key4->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'mdc2');
   $radiobox->add($key4);

   $key5 = Gtk::RadioButton->new('MD4', $key1);
   $key5->set_active(1) 
      if(defined($opts->{'digest'}) && $opts->{'digest'} eq 'md4');
   $key5->signal_connect('toggled', \&_toggle_to_var, \$opts->{'digest'}, 'md4');
   $radiobox->add($key5);

   $catable->attach_defaults($radiobox, 1, 2, 15, 16);

   $box->show_all();

   return;
}

#
# subroutines for pop-up boxes
# 
sub show_help {
   my $self = shift;

   $self->print_info(gettext("You are kidding, are you??"));

   return;
}

#
#  About dialog
#
sub about {
   my $self = shift;

   my $aboutdialog = Gnome::About->new(
         'TinyCA', $self->{'version'}, 
         '(C) 2002 Stephan Martin',
         'Stephan Martin <sm@sm-zone.net>', 
         "http://tinyca.sm-zone.net\n\n".
         "This program is free software published under the GNU Public License");

   $aboutdialog->set_title(('About').' TinyCA');
   $aboutdialog->set_position('mouse' );
   $aboutdialog->set_policy(1, 1, 0);
   $aboutdialog->set_modal(1);
   $aboutdialog->realize();
   $aboutdialog->show();
   
   return;
}

#
#  Error message box, kills application
#
sub print_error {
   my ($self, $t) = @_;
   
   my $box = Gnome::MessageBox->new($t, 'error');
   $box->close_hides(0);
   $box->set_close(1);
   $box->set_position('mouse' );
   $box->set_policy(0, 0, 0);
   $box->set_modal(1);
   $box->realize();

   my $button = Gnome::Stock->button('Button_Ok');
   $button->signal_connect('clicked', sub { $self->_exit_clean(1) });
   $button->can_default(1);

   my $actionarea = Gtk::HButtonBox->new();
   $box->vbox->add($actionarea);
   $actionarea->pack_start($button, 1, 1, 0);
   $actionarea->set_layout('end');
   $actionarea->set_spacing(6);
   $actionarea->set_child_ipadding(7, 0);

   $button->grab_default();

   $box->show_all();
}

#
#  Warning message box
#
sub print_warning {
   my ($self, $t) = @_;
   
   my $box = Gnome::MessageBox->new($t, 'warning');
   $box->close_hides(0);
   $box->set_close(1);
   $box->set_position('mouse' );
   $box->set_policy(0, 0, 0);
   $box->set_modal(1);
   $box->realize();

   my $button = Gnome::Stock->button('Button_Ok');
   $button->signal_connect('clicked', sub { $box->destroy() });
   $button->can_default(1);

   my $actionarea = Gtk::HButtonBox->new();
   $box->vbox->add($actionarea);
   $actionarea->pack_start($button, 1, 1, 0);
   $actionarea->set_layout('end');
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
   my ($self, $t) = @_;
   
   my $box = Gnome::MessageBox->new($t, 'info');
   $box->close_hides(0);
   $box->set_close(1);
   $box->set_position('mouse' );
   $box->set_policy(0, 0, 0);
   $box->set_modal(1);
   $box->realize();

   my $button = Gnome::Stock->button('Button_Ok');
   $button->signal_connect('clicked', sub { $box->destroy() });
   $button->can_default(1);

   my $actionarea = Gtk::HButtonBox->new();
   $box->vbox->add($actionarea);
   $actionarea->pack_start($button, 1, 1, 0);
   $actionarea->set_layout('end');
   $actionarea->set_spacing(6);
   $actionarea->set_child_ipadding(7, 0);

   $button->grab_default();

   $box->show_all();

   return;
}

#
# get confirmation for deleting a request
#
sub show_del_confirm {
   my ($self, $file, $type) = @_;

   my $t = '';
   if($type eq 'req') {
      $t = gettext("Do you really want to delete the selected Request?");
   }elsif($type eq 'key') {
      $t = gettext("Do you really want to delete the selected Key?");
   }elsif($type eq 'cert') {
      $t = gettext("Do you really want to delete the selected Certificate?");
   }else{
      $self->print_error("Invalid type in show_del_confirm(): ".$type);
   }
      
   my $box = Gnome::MessageBox->new($t, 'question');
   $box->close_hides(0);
   $box->set_close(1);
   $box->set_position('mouse' );
   $box->set_policy(0, 0, 0);
   $box->set_modal(1);
   $box->realize();

   my $actionarea = Gtk::HButtonBox->new();
   $actionarea->set_layout('spread');
   $actionarea->set_spacing(6);
   $actionarea->set_child_ipadding(7, 0);
   $box->vbox->add($actionarea);

   my $button = Gnome::Stock->button('Button_Ok');
   if($type eq 'req') {
      $button->signal_connect('clicked', sub { 
           $self->{'REQ'}->del_req($self, $file);
           $box->destroy() });
   }elsif($type eq 'key') {
      $button->signal_connect('clicked', sub { 
           $self->{'KEY'}->del_key($self, $file);
           $box->destroy() });
   }elsif($type eq 'cert') {
      $button->signal_connect('clicked', sub {
            $self->{'CERT'}->del_cert($self, $file);
            $box->destroy() });
   }

   $actionarea->pack_start($button, 1, 1, 0);
   $button->can_default(1);
   $button->grab_default();

   $button = Gnome::Stock->button('Button_Cancel');
   $button->signal_connect('clicked', sub { $box->destroy(); return });
   $actionarea->pack_start($button, 1, 1, 0);

   $box->show_all();
}

#
# show warning - overwrite key
#
sub show_req_overwrite_warning {
   my ($self, $opts) = @_;

   my ($box, $actionarea, $button, $t);

   $t = gettext("The Key or the Request is already existing!");
   $t .= "\n\n";
   $t .= gettext("If the corresponding certificate it\'s not expired or revoked ");
   $t .= gettext("you won\'t be able to sign this request!");

   $box = Gnome::MessageBox->new($t, 'warning');
   $box->close_hides(0);
   $box->set_close(1);
   $box->set_position('mouse' );
   $box->set_policy(0, 0, 0);
   $box->set_modal(1);
   $box->realize();

   $actionarea = Gtk::HButtonBox->new();
   $box->vbox->add($actionarea);
   $actionarea->set_layout('end');
   $actionarea->set_spacing(6);
   $actionarea->set_child_ipadding(7, 0);

   $button = Gnome::Stock->button('Button_Ok');
   $button->signal_connect('clicked', 
         sub { $self->{'REQ'}->create_req($self, $opts); $box->destroy() });
   $actionarea->pack_start($button, 1, 1, 0);

   $button = Gnome::Stock->button('Button_Cancel');
   $button->signal_connect('clicked', sub { 
         $box->destroy() });
   $button->can_default(1);
   $actionarea->pack_start($button, 1, 1, 0);
   $button->grab_default();

   $box->show_all();

   return;
}

#
# show warning - certificate expiration date
#
sub show_req_date_warning {
   my ($self, $opts) = @_;

   my ($box, $button_ok, $button_cancel, $t);

   $t = gettext("The Certificate will be longer valid than your CA!");
   $t .= "\n";
   $t .= gettext("This may cause problems with some software!!");

   $button_ok = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $opts->{'ignoredate'} = 'true';
               $self->{'REQ'}->get_sign_req($self, $opts, $box); });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', sub { 
         $self->show_req_sign_dialog($opts);
         $box->destroy();
         });
   $button_cancel->can_default(1);

   $box = _dialog_box($self,
         gettext("Expirationdate Warning"), $t,
         $button_ok, $button_cancel);

   $button_cancel->grab_default();

   $box->show_all();

}

#
# get confirmation for overwriting certificate
#
sub show_cert_overwrite_confirm {
   my ($self, $opts) = @_;

   my($box, $button_ok, $button_cancel, $label);
   
   $button_ok = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { $opts->{'overwrite'} = 'true';
               $self->{'REQ'}->get_sign_req($self, $opts, $box) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->can_default(1);
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("Overwrite Certificate"), gettext("Overwrite Certificate"),
         $button_ok, $button_cancel);

   $button_cancel->grab_default();

   $label = _create_label($self, 
         gettext("There seems to be an certificate already."), 'center', 1, 0);
   $box->vbox->add($label);

   $label = _create_label($self, 
         gettext("Creating a new one (overwrite) will fail if it\'s not revoked or expired!"), 
         'center', 1, 0);
   $box->vbox->add($label);


   $label = _create_label($self, 
         gettext("Really try to overwrite the Certificate?"), 'center', 1, 0);
   $box->vbox->add($label);

   $box->show_all();
   return;
}

#
# main screen for configuration
#
sub show_configbox {
   my ($self, $name) = @_;

   my ($box, $nb, $vbox, $label, $table, $rows, @options, @options_ca, $entry,
         $key, $separator, $t, $combo, %words, @combostrings);

   %words = (
    'none'                  => gettext("Not set"),
    'user'                  => gettext("Ask User"),
    'critical'              => gettext("critical"),
    'noncritical'           => gettext("not critical"),
    'emailcopy'             => gettext("Copy Email"),
    'dns'                   => gettext("DNS Name"),
    'ip'                    => gettext("IP Address"),
    'mail'                  => gettext("Email"),
    'server'                => gettext("SSL Server"),
    'key'                   => gettext("Key Encipherment"),
    'sig'                   => gettext("Digital Signature"),
    'keysig'                => gettext("Key Encipherment, Digital Signature"),
    'objsign'               => gettext("Object Signing"),
    'client, objsign'       => gettext("SSL Client, Object Signing"),
    'client, email'         => gettext("SSL Client, Email(S/MIME)"),
    'client'                => gettext("SSL Client"),
    'email'                 => gettext("Email(S/MIME)"),
    'client, email, objsign'=> gettext("SSL Client, Email, Object Signing"),
    'objCA'                 => gettext("Object Signing CA"),
    'emailCA'               => gettext("S/MIME CA"),
    'sslCA'                 => gettext("SSL CA"),
    'sslCA, emailCA'        => gettext("SSL CA, S/MIME CA"),
    'sslCA, objCA'          => gettext("SSL CA, Object Signing CA"),
    'emailCA, objCA'        => gettext("S/MIME CA, Object Signing CA"),
    'sslCA, emailCA, objCA' => gettext("SSL CA, S/MIME CA, Object Signing CA"),
    'keyCertSign'           => gettext("Certificate Signing"),
    'cRLSign'               => gettext("CRL Signing"),
    'keyCertSign, cRLSign'  => gettext("Certificate Signing, CRL Signing"),
    gettext("Not set")                             => 'none',
    gettext("Ask User")                            => 'user',
    gettext("critical")                            => 'critical',
    gettext("not critical")                        => 'noncritical',
    gettext("Copy Email")                          => 'emailcopy',
    gettext("DNS Name")                            => 'dns',
    gettext("Email")                               => 'email',
    gettext("IP Address")                          => 'ip',
    gettext("SSL Server")                          => 'server',
    gettext("Key Encipherment")                    => 'key',
    gettext("Digital Signature")                   => 'sig',
    gettext("Key Encipherment, Digital Signature") => 'keysig',
    gettext("Object Signing")                      => 'objsign',
    gettext("Email(S/MIME)")                       => 'email',
    gettext("SSL Client, Email(S/MIME)")           => 'client, email',
    gettext("SSL Client")                          => 'client',
    gettext("SSL Client, Object Signing")          => 'client, objsign',
    gettext("SSL Client, Email, Object Signing")   => 'client, email, objsign',
    gettext("Object Signing CA")                   => 'objCA',
    gettext("S/MIME CA")                           => 'emailCA',
    gettext("SSL CA")                              => 'sslCA',
    gettext("SSL CA, S/MIME CA")                   => 'sslCA, emailCA',
    gettext("SSL CA, Object Signing CA")           => 'sslCA, objCA',
    gettext("S/MIME CA, Object Signing CA")        => 'emailCA, objCA',
    gettext("SSL CA, S/MIME CA, Object Signing CA")=> 'sslCA, emailCA, objCA',
    gettext("Certificate Signing")                 => 'keyCertSign',
    gettext("CRL Signing")                         => 'cRLSign',
    gettext("Certificate Signing, CRL Signing")    => 'keyCertSign, cRLSign'
   );

   if(not defined($name)) {
      $name = $self->{'CA'}->{'actca'};
   }
   if(not defined($name)) {
      $self->print_warning(gettext("Can't get CA name"));
      return;
   }

   $self->{'TCONFIG'}->init_config($self, $name);

   $box = Gnome::PropertyBox->new();
   $box->set_position('mouse');
   $box->set_policy(0, 0, 0);
   $box->set_modal(0);

   $box->signal_connect('apply', 
         sub { $self->{'TCONFIG'}->write_config($self, $name) });

   $t = gettext("All Settings are written unchanged to openssl.conf.\nSo please study the documentation of OpenSSL if you don't know exactly what to do.\nIf you are still unsure - keep the defaults and everything is expected to work fine.");
   $box->signal_connect('help', 
         sub { $self->print_info($t) });

   $nb = $box->notebook();
   $nb->set_tab_pos('top');
   $nb->set_show_tabs(1);
   $nb->set_show_border(1);
   $nb->set_scrollable(0);

   # first page: vbox with warnings :-)
   $vbox = Gtk::VBox->new(0, 0);

   $label = _create_label($self, 
         gettext("OpenSSL Configuration"), 'center', 0,0);

   $nb->append_page($vbox, $label);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("OpenSSL Configuration"), 'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = _create_label($self, 
         gettext("Only change these options, if you really know, what you are doing!!"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = _create_label($self, 
         gettext("You should be aware, that some options may break some crappy software!!"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);


   $label = _create_label($self, 
         gettext("If you are unsure: leave the defaults untouched"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
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
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("These Settings are passed to OpenSSL for creating Server Certificates"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("Multiple Values can be separated by \",\""),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 1, 1, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = _create_label($self, gettext("Server Certificate Settings"), 
         'center', 0, 0);
   $label = Gtk::Label->new(gettext("Server Certificate Settings"));

   $nb->append_page($vbox, $label);

   # special option subjectAltName
   $label = _create_label($self, 
         gettext("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $self->{'radiobox'} = Gtk::HBox->new(0, 0);
   $self->{'radio1'} = Gtk::RadioButton->new(gettext($words{'ip'}));
   $self->{'radio1'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'}, 'ip', 
         $box);
   $self->{'radiobox'}->add($self->{'radio1'});

   $self->{'radio2'} = Gtk::RadioButton->new(
         gettext($words{'dns'}), $self->{'radio1'});
   $self->{'radio2'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'}, 'dns', 
         $box);
   $self->{'radiobox'}->add($self->{'radio2'});

   if($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'} 
         eq 'ip') {
      $self->{'radio1'}->set_active(1)
   }elsif($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'} 
         eq 'dns') {
      $self->{'radio2'}->set_active(1)
   }

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'user'}, $words{'emailcopy'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'})) {
     if($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} 
        eq 'user') {
        $self->{'radio1'}->set_sensitive(1);
        $self->{'radio2'}->set_sensitive(1);

        $combo->entry->set_text($words{'user'});
     }elsif($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $combo->entry->set_text($words{'emailcopy'});
        $self->{'radio1'}->set_sensitive(0);
        $self->{'radio2'}->set_sensitive(0);
     }elsif($self->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'} 
        eq 'none') { 
        $combo->entry->set_text($words{'none'});
        $self->{'radio1'}->set_sensitive(0);
        $self->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($words{'none'});
      $self->{'radio1'}->set_sensitive(0);
      $self->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var_san, $combo->entry, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'}, 
         $box, \%words, $self->{'radio1'},  $self->{'radio2'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($self->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option keyUsage
   $label = _create_label($self, 
         gettext("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $self->{'radiobox'} = Gtk::HBox->new(0, 0);
   $self->{'radio1'} = Gtk::RadioButton->new(gettext($words{'critical'}));
   if($self->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'} eq 'critical') {
      $self->{'radio1'}->set_active(1)
   }
   $self->{'radio1'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'}, 'critical', 
         $box);
   $self->{'radiobox'}->add($self->{'radio1'});

   $self->{'radio2'} = Gtk::RadioButton->new(
         gettext($words{'noncritical'}), $self->{'radio1'});
   if($self->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'} eq 'noncritical') {
      $self->{'radio2'}->set_active(1)
   }
   $self->{'radio2'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'}, 'noncritical', 
         $box);
   $self->{'radiobox'}->add($self->{'radio2'});

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'sig'}, 
         $words{'key'}, $words{'keysig'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($self->{'TCONFIG'}->{'server_cert'}->{'keyUsage'})) {
     if($self->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} 
        ne 'none') {
        $self->{'radio1'}->set_sensitive(1);
        $self->{'radio2'}->set_sensitive(1);

        if($self->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'sig') {
           $combo->entry->set_text($words{'sig'});
        }elsif($self->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'key') {
           $combo->entry->set_text($words{'key'});
        }elsif($self->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'keysig') {
           $combo->entry->set_text($words{'keysig'});
        }else {
           $combo->entry->set_text($words{'none'});
           $self->{'radio1'}->set_sensitive(0);
           $self->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combo->entry->set_text($words{'none'});
        $self->{'radio1'}->set_sensitive(0);
        $self->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($words{'none'});
      $self->{'radio1'}->set_sensitive(0);
      $self->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var_san, $combo->entry, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'keyUsage'}, 
         $box, \%words, $self->{'radio1'},  $self->{'radio2'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($self->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = _create_label($self, 
         gettext("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'server'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsCertType'})) {
      $combo->entry->set_text(
            $words{$self->{'TCONFIG'}->{'server_cert'}->{'nsCertType'}});
   } else {
      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var, $combo->entry, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'nsCertType'}, $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsSslServer
   $label = _create_label($self, 
         gettext("Netscape SSL Server Name (nsSslServerName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}) && 
         $self->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'} 
         eq 'user') { 
      $combo->entry->set_text($words{'user'});
   } else {
      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var, $combo->entry, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}, 
         $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRevocationUrl
   $label = _create_label($self, 
         gettext("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}) && 
         $self->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'} 
         eq 'user') { 
      $combo->entry->set_text($words{'user'});
   } else {
      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var, $combo->entry, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}, 
         $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRenewalUrl
   $label = _create_label($self, 
         gettext("Netscape Renewal URL (nsRenewalUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($self->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}) && 
         $self->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'} 
         eq 'user') { 
      $combo->entry->set_text($words{'user'});
   } else {
      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var, $combo->entry, 
         \$self->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}, 
         $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # standard options
   foreach $key (@options) { 
      $entry = _entry_to_table($self, "$key:",
            \$self->{'TCONFIG'}->{'server_cert'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   foreach $key (@options_ca) {
      $entry = _entry_to_table($self, "$key:",
            \$self->{'TCONFIG'}->{'server_ca'}->{$key}, 
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
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("These Settings are passed to OpenSSL for creating Client Certificates"), 
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 1, 1, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = _create_label($self, gettext("Client Certificate Settings"),
         'center', 0, 0);
   $nb->append_page($vbox, $label);

   # special option subjectAltName
   $label = _create_label($self, 
         gettext("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $self->{'radiobox'} = Gtk::HBox->new(0, 0);
   $self->{'radio1'} = Gtk::RadioButton->new(gettext($words{'ip'}));
   $self->{'radio1'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}, 'ip', 
         $box);
   $self->{'radiobox'}->add($self->{'radio1'});

   $self->{'radio2'} = Gtk::RadioButton->new(
         gettext($words{'dns'}), $self->{'radio1'});
   $self->{'radio2'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}, 'dns', 
         $box);
   $self->{'radiobox'}->add($self->{'radio2'});

   $self->{'radio3'} = Gtk::RadioButton->new(
         gettext($words{'mail'}), $self->{'radio1'});
   $self->{'radio3'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}, 'mail', 
         $box);
   $self->{'radiobox'}->add($self->{'radio3'});

   if($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'ip') {
      $self->{'radio1'}->set_active(1)
   }elsif($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'dns') {
      $self->{'radio2'}->set_active(1)
   }elsif($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'} 
         eq 'mail') {
      $self->{'radio3'}->set_active(1)
   }

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'user'}, $words{'emailcopy'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'})) {
     if($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} 
        eq 'user') {
        $self->{'radio1'}->set_sensitive(1);
        $self->{'radio2'}->set_sensitive(1);
        $self->{'radio3'}->set_sensitive(1);

        $combo->entry->set_text($words{'user'});
     }elsif($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $self->{'radio1'}->set_sensitive(0);
        $self->{'radio2'}->set_sensitive(0);
        $self->{'radio3'}->set_sensitive(0);

        $combo->entry->set_text($words{'emailcopy'});
     }elsif($self->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'} 
        eq 'none') { 
        $self->{'radio1'}->set_sensitive(0);
        $self->{'radio2'}->set_sensitive(0);
        $self->{'radio3'}->set_sensitive(0);

        $combo->entry->set_text($words{'none'});
     }
   } else { 
      $self->{'radio1'}->set_sensitive(0);
      $self->{'radio2'}->set_sensitive(0);
      $self->{'radio3'}->set_sensitive(0);

      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var_san, $combo->entry, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'}, 
         $box, \%words, 
         $self->{'radio1'},  $self->{'radio2'}, $self->{'radio3'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($self->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option keyUsage
   $label = _create_label($self, 
         gettext("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $self->{'radiobox'} = Gtk::HBox->new(0, 0);
   $self->{'radio1'} = Gtk::RadioButton->new(gettext($words{'critical'}));
   if($self->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'} eq 'critical') {
      $self->{'radio1'}->set_active(1)
   }
   $self->{'radio1'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'}, 'critical', 
         $box);
   $self->{'radiobox'}->add($self->{'radio1'});

   $self->{'radio2'} = Gtk::RadioButton->new(
         gettext($words{'noncritical'}), $self->{'radio1'});
   if($self->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'} eq 'noncritical') {
      $self->{'radio2'}->set_active(1)
   }
   $self->{'radio2'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'}, 'noncritical', 
         $box);
   $self->{'radiobox'}->add($self->{'radio2'});

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'sig'}, 
         $words{'key'}, $words{'keysig'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($self->{'TCONFIG'}->{'client_cert'}->{'keyUsage'})) {
     if($self->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} 
        ne 'none') {
        $self->{'radio1'}->set_sensitive(1);
        $self->{'radio2'}->set_sensitive(1);

        if($self->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'sig') {
           $combo->entry->set_text($words{'sig'});
        }elsif($self->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'key') {
           $combo->entry->set_text($words{'key'});
        }elsif($self->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'keysig') {
           $combo->entry->set_text($words{'keysig'});
        }else {
           $combo->entry->set_text($words{'none'});
           $self->{'radio1'}->set_sensitive(0);
           $self->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combo->entry->set_text($words{'none'});
        $self->{'radio1'}->set_sensitive(0);
        $self->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($words{'none'});
      $self->{'radio1'}->set_sensitive(0);
      $self->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var_san, $combo->entry, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'keyUsage'}, 
         $box, \%words, $self->{'radio1'},  $self->{'radio2'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($self->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = _create_label($self, 
         gettext("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'objsign'}, $words{'email'}, 
         $words{'client'}, $words{'client, email'}, $words{'client, objsign'},
         $words{'client, email, objsign'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($self->{'TCONFIG'}->{'client_cert'}->{'nsCertType'})) {
      $combo->entry->set_text(
            $words{$self->{'TCONFIG'}->{'client_cert'}->{'nsCertType'}});
   } else {
      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var, $combo->entry, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'nsCertType'}, $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRevocationUrl
   $label = _create_label($self, 
         gettext("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($self->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}) && 
         $self->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'} 
         eq 'user') { 
      $combo->entry->set_text($words{'user'});
   } else {
      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var, $combo->entry, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}, 
         $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRenewalUrl
   $label = _create_label($self, 
         gettext("Netscape Renewal URL (nsRenewalUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($self->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}) && 
         $self->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'} 
         eq 'user') { 
      $combo->entry->set_text($words{'user'});
   } else {
      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var, $combo->entry, 
         \$self->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}, 
         $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # standard options
   foreach $key (@options) { 
      $entry = _entry_to_table($self, "$key:",
            \$self->{'TCONFIG'}->{'client_cert'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   foreach $key (@options_ca) {
      $entry = _entry_to_table($self, "$key:",
            \$self->{'TCONFIG'}->{'client_ca'}->{$key}, 
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
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("These Settings are passed to OpenSSL for creating CA Certificates"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("Multiple Values can be separated by \",\""),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 1, 1, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = _create_label($self, gettext("CA Certificate Settings"), 
         'center', 0, 0);
   $label = Gtk::Label->new(gettext("CA Certificate Settings"));

   $nb->append_page($vbox, $label);

   # special option subjectAltName
   $label = _create_label($self, 
         gettext("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'emailcopy'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($self->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'})) {
     if($self->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'} 
        eq 'emailcopy') { 
        $combo->entry->set_text($words{'emailcopy'});
        $self->{'radio1'}->set_sensitive(0);
        $self->{'radio2'}->set_sensitive(0);
     }elsif($self->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'} 
        eq 'none') { 
        $combo->entry->set_text($words{'none'});
        $self->{'radio1'}->set_sensitive(0);
        $self->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($words{'none'});
      $self->{'radio1'}->set_sensitive(0);
      $self->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var_san, $combo->entry, 
         \$self->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'}, 
         $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsCerttype
   $label = _create_label($self, 
         gettext("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, 
                    $words{'emailCA'},
                    $words{'sslCA'},
                    $words{'objCA'},
                    $words{'sslCA, emailCA'},
                    $words{'sslCA, objCA'},
                    $words{'emailCA, objCA'},
                    $words{'sslCA, emailCA, objCA'} 
                    );
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($self->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'})) {
      $combo->entry->set_text(
            $words{$self->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}});
   } else {
      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var, $combo->entry, 
         \$self->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}, $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # special option keyUsage
   $label = _create_label($self, 
         gettext("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $self->{'radiobox'} = Gtk::HBox->new(0, 0);
   $self->{'radio1'} = Gtk::RadioButton->new(gettext($words{'critical'}));
   if($self->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'critical') {
      $self->{'radio1'}->set_active(1)
   }
   $self->{'radio1'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'critical', 
         $box);
   $self->{'radiobox'}->add($self->{'radio1'});

   $self->{'radio2'} = Gtk::RadioButton->new(
         gettext($words{'noncritical'}), $self->{'radio1'});
   if($self->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'noncritical') {
      $self->{'radio2'}->set_active(1)
   }
   $self->{'radio2'}->signal_connect('toggled', \&_toggle_to_var_pref, 
         \$self->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'noncritical', 
         $box);
   $self->{'radiobox'}->add($self->{'radio2'});

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, 
                    $words{'keyCertSign'}, 
                    $words{'cRLSign'}, 
                    $words{'keyCertSign, cRLSign'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);

   if(defined($self->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'})) {
     if($self->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} 
        ne 'none') {
        $self->{'radio1'}->set_sensitive(1);
        $self->{'radio2'}->set_sensitive(1);

        if($self->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'keyCertSign') {
           $combo->entry->set_text($words{'keyCertSign'});
        }elsif($self->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'cRLSign') {
           $combo->entry->set_text($words{'cRLSign'});
        }elsif($self->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 
                                                 'keyCertSign, cRLSign') {
           $combo->entry->set_text($words{'keyCertSign, cRLSign'});
        }else {
           $combo->entry->set_text($words{'none'});
           $self->{'radio1'}->set_sensitive(0);
           $self->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combo->entry->set_text($words{'none'});
        $self->{'radio1'}->set_sensitive(0);
        $self->{'radio2'}->set_sensitive(0);
     }
   } else { 
      $combo->entry->set_text($words{'none'});
      $self->{'radio1'}->set_sensitive(0);
      $self->{'radio2'}->set_sensitive(0);
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var_san, $combo->entry, 
         \$self->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'}, 
         $box, \%words, $self->{'radio1'},  $self->{'radio2'});
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   $table->attach_defaults($self->{'radiobox'}, 1, 2, $rows-1, $rows);
   $rows++;

   # special option nsRevocationUrl
   $label = _create_label($self, 
         gettext("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $rows-1, $rows);

   $combo = Gtk::Combo->new();
   @combostrings = ($words{'none'}, $words{'user'});
   $combo->set_popdown_strings(@combostrings);
   $combo->set_use_arrows(1);
   $combo->set_value_in_list(1, 0);
   if(defined($self->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'}) && 
         $self->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'} 
         eq 'user') { 
      $combo->entry->set_text($words{'user'});
   } else {
      $combo->entry->set_text($words{'none'});
   }
   $combo->entry->signal_connect('changed', \&_entry_to_var, $combo->entry, 
         \$self->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'}, 
         $box, \%words);
   $table->attach_defaults($combo, 1, 2, $rows-1, $rows);
   $rows++;

   # standard options
   foreach $key (@options) { 
      $entry = _entry_to_table($self, "$key:",
            \$self->{'TCONFIG'}->{'v3_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   foreach $key (@options_ca) {
      $entry = _entry_to_table($self, "$key:",
            \$self->{'TCONFIG'}->{'ca_ca'}->{$key}, 
            $table, $rows-1, 1, $box);

      $rows++;
      $table->resize($rows, 2);
   }

   # fifth page: crl settings
   @options = qw(
         default_crl_days
         );

   $vbox = Gtk::VBox->new(0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("These Settings are passed to OpenSSL for creating Certificate Revocation Lists"), 
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk::HSeparator->new();
   $vbox->pack_start($separator, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $vbox->pack_start($table, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = _create_label($self, 
         gettext("Revocation List Settings"), 'center', 0, 0);
   $nb->append_page($vbox, $label);

   foreach $key (@options) { 
      $entry = _entry_to_table($self, "$key:",
            \$self->{'TCONFIG'}->{'server_ca'}->{$key}, 
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
   my ($self, $opts, $mode) = @_;

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
      $self->print_warning(gettext("Can't get CA name"));
      return;
   }

   $self->{'TCONFIG'}->init_config($self, $opts->{'name'});
   
   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { 
            $self->{'TCONFIG'}->write_config($self, $opts->{'name'});
            $opts->{'configured'} = 1;
            $self->{'CA'}->create_ca($self, $opts, $box, $mode) });

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = _dialog_box($self, 
         gettext("CA Configuration"), gettext("CA Configuration"), 
         $button_ok, $button_cancel);


   $label = _create_label($self, ' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $label = _create_label($self, 
         gettext("These Settings are passed to OpenSSL for creating this CA Certificate"), 
         'center', 0, 1);
   $box->vbox->pack_start($label, 0, 0, 0);

   $label = _create_label($self, 
         gettext("and the CA Certificates of every SubCA, created with this CA."),
         'center', 0, 1);
   $box->vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, 
         gettext("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $label = _create_label($self, 
         gettext("If you are unsure: leave the defaults untouched"), 
         'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $box->vbox->add($table);

   
   foreach $key (@options) {
      $entry = _entry_to_table($self, "$key:",
            \$self->{'TCONFIG'}->{'v3_ca'}->{$key}, $table, $rows-1, 1);

      $rows++;
      $table->resize($rows, 2);
   }

   $box->show_all();

   return;
}

#
# ask if the CA shall be converted
#
sub show_ca_convert_dialog {
   my ($self, $opts) = @_;

   my($box, $label, $button_ok, $button_cancel, $t);

   $button_ok     = Gnome::Stock->button('Button_Ok');
   $button_ok->signal_connect('clicked', 
         sub { 
            $opts->{'doconv'} = 1;
            $self->{'CA'}->open_ca($self, $opts, $box) 
         }
   );
   $button_ok->can_default(1);

   $button_cancel = Gnome::Stock->button('Button_Cancel');
   $button_cancel->signal_connect('clicked', 
         sub { 
            $opts->{'noconv'} = 1;
            $self->{'CA'}->open_ca($self, $opts, $box) 
         }
   );

   $box = _dialog_box($self,
         gettext("Convert CA"), gettext("Convert CA"),
         $button_ok, $button_cancel);

   $button_ok->grab_default();

   $label = _create_label($self, ' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $t = gettext("This CA seems to be created with openssl 0.9.6x. And it seems like you have switched to openssl 0.9.7x.");

   $label = _create_label($self, $t, 'center', 1, 0);
   $box->vbox->add($label);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $t = gettext("You won't be able to revoke the existing certificates without converting the index file of this CA to the new format.");

   $label = _create_label($self, $t, 'center', 1, 0);
   $box->vbox->add($label);
   
   $label = _create_label($self, ' ', 'center', 0, 0);
   $box->vbox->pack_start($label, 0, 0, 0);

   $t = gettext("Attention: it will not be easy to switch back, this has to be done manually");
   $label = _create_label($self, $t, 'center', 1, 0);
   $box->vbox->add($label);

   $box->show_all();

   return;
}

#
# create popup menu for keys
#
sub _create_key_menu {
   my $self = shift;

   my ($menu_item, @menus, $width, $style, $font, $string);

   $self->{'keymenu'} = Gtk::Menu->new();

   @menus = ( gettext("Export Key"), gettext("Delete Key"));

   $string = 0;
   foreach(@menus) {
      $string = $_ if(length($_) > length($string));
   }

   $menu_item = Gnome::Stock->menu_item('Menu_Save', gettext("Export Key"));

   $style = $menu_item->get_style();
   $font  = $style->font();
   $width = $font->string_width($string);
   $width += 50;

   $menu_item->set_usize($width, 0);
   
   $self->{'keymenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->{'KEY'}->get_export_key($self) });

   $menu_item = Gnome::Stock->menu_item('Menu_Trash',
         gettext("Delete Key"));
   $self->{'keymenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->{'KEY'}->get_del_key($self) });

   $self->{'keymenu'}->show_all();

   return;
}

#
# called on rightclick in keylist
#
sub _show_key_menu {
   my ($clist, $self, $event) = @_;

   if ((defined($event->{'type'})) &&
         $event->{'button'} == 3) {
      $self->{'keymenu'}->popup( 
            undef,
            undef,
            0,
            $event->{'button'},
            undef);

      return(1);
   }

   return(0);
}

#
# create popup menus for certificates
#
sub _create_cert_menu {
   my $self = shift;

   my ($menu_item, @menus, $width, $style, $font, $string);

   $self->{'certmenu'} = Gtk::Menu->new();

   @menus = (
         gettext("Certificate Details"),
         gettext("View Certificate"),
         gettext("Export Certificate"),
         gettext("Revoke Certificate"),
         gettext("Delete Certificate"));

   $string = 0;
   foreach(@menus) {
      $string = $_ if(length($_) > length($string));
   }

   $menu_item = Gnome::Stock->menu_item('Menu_Search', 
         gettext("Certificate Details"));

   $style = $menu_item->get_style();
   $font  = $style->font();
   $width = $font->string_width($string);
   $width += 50;

   $menu_item->set_usize($width, 0);
   
   $self->{'certmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->show_details('cert') });

   $menu_item = Gnome::Stock->menu_item('Menu_Search', 
         gettext("View Certificate"));
   $self->{'certmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->show_text('cert') });

   $menu_item = Gtk::MenuItem->new();
   $self->{'certmenu'}->append($menu_item);

   $menu_item = Gnome::Stock->menu_item('Menu_Save',
         gettext("Export Certificate"));
   $self->{'certmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->{'CERT'}->get_export_cert($self) });

   $menu_item = Gnome::Stock->menu_item('Menu_Stop',
         gettext("Revoke Certificate"));
   $self->{'certmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->{'CERT'}->get_revoke_cert($self) });

   $menu_item = Gnome::Stock->menu_item('Menu_Trash',
         gettext("Delete Certificate"));
   $self->{'certmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->{'CERT'}->get_del_cert($self) });

   $self->{'certmenu'}->show_all();

   return;
}

#
# called on rightclick in certlist
#
sub _show_cert_menu {
   my ($clist, $self, $event) = @_;

   if ((defined($event->{'type'})) &&
         $event->{'button'} == 3) {
      $self->{'certmenu'}->popup( 
            undef,
            undef,
            0,
            $event->{'button'},
            undef);

      return(1);
   }

   return(0);
}

#
# create popup menus for requests
#
sub _create_req_menu {
   my $self = shift;
   
   my ($menu_item, $opts, @menus, $width, $style, $font, $string);

   $self->{'reqmenu'} = Gtk::Menu->new();

   @menus = (
         gettext("Request Details"),
         gettext("View Request"),
         gettext("Sign Request (Server)"),
         gettext("Sign Request (Client)"),
         gettext("Import Request"),
         gettext("New Request"),
         gettext("Delete Request"));

   $string = 0;
   foreach(@menus) {
      $string = $_ if(length($_) > length($string));
   }

   $menu_item = Gnome::Stock->menu_item('Menu_Search',
         gettext("Request Details"));

   $style = $menu_item->get_style();
   $font  = $style->font();
   $width = $font->string_width($string);
   $width += 50;

   $menu_item->set_usize($width, 0);

   $self->{'reqmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->show_details('req') });

   $menu_item = Gnome::Stock->menu_item('Menu_Search',
         gettext("View Request"));
   $self->{'reqmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->show_text('req') });

   $menu_item = Gtk::MenuItem->new();
   $self->{'reqmenu'}->append($menu_item);

   $menu_item = Gnome::Stock->menu_item('Menu_Properties',
         gettext("Sign Request (Server)"));
   $self->{'reqmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $opts->{'type'} = 'server';
         $self->{'REQ'}->get_sign_req($self, $opts) });

   $menu_item = Gnome::Stock->menu_item('Menu_Properties',
         gettext("Sign Request (Client)"));
   $self->{'reqmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $opts->{'type'} = 'client';
         $self->{'REQ'}->get_sign_req($self, $opts) });

   $menu_item = Gtk::MenuItem->new();
   $self->{'reqmenu'}->append($menu_item);

   $menu_item = Gnome::Stock->menu_item('Menu_Revert',
         gettext("Import Request"));
   $self->{'reqmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->{'REQ'}->get_import_req($self) });

   $menu_item = Gnome::Stock->menu_item('Menu_New',
         gettext("New Request"));
   $self->{'reqmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->{'REQ'}->get_req_create($self) });

   $menu_item = Gtk::MenuItem->new();
   $self->{'reqmenu'}->append($menu_item);

   $menu_item = Gnome::Stock->menu_item('Menu_Trash',
         gettext("Delete Request"));
   $self->{'reqmenu'}->append($menu_item);
   $menu_item->signal_connect( 'activate', 
         sub { $self->{'REQ'}->get_del_req($self) });

   $self->{'reqmenu'}->show_all();

   return;
}

#
# called on rightclick in reqlist
#
sub _show_req_menu {
   my ($clist, $self, $event) = @_;

   if ((defined($event->{'type'})) &&
         $event->{'button'} == 3) {
      $self->{'reqmenu'}->popup( 
            undef,
            undef,
            0,
            $event->{'button'},
            undef);

      return(1);
   }

   return(0);
}

#
# called if certificate is selected
# fill in the certificate details in the window
#
sub _fill_info {
   my ($clist, $self, $mode, $row, $column) = @_;

   my ($ind, $ca, $item, $status, $itemname, $parsed, $label, $bottombox,
         $righttable, $rightbox, $lefttable, $leftbox, $textbox, @fields, $t);

   $ca  = $self->{'CA'}->{'actca'};
   
   if($mode eq 'cert') {
      $ind = $clist->get_text($row, 8);
   }elsif($mode eq 'req') {
      $ind = $clist->get_text($row, 7);
   }else {
         $self->print_error(gettext("Invalid mode for: _fill_info(): ").$mode);
      return;
   }

   if(not defined($ind)) {
      if($mode eq 'cert') {
         $t = gettext("Please select a Certificate first");
      } else {
         $t = gettext("Please select a Request first");
      }
      $self->print_error($t);
      return;
   }

   if($mode eq 'cert') {
      ($item, $status) = split(/\%/, $self->{'CERT'}->{'certlist'}->[$ind]);
   }else{
      $item = $self->{'REQ'}->{'reqlist'}->[$ind];
   }

   $itemname = MIME::Base64::encode($item, '');

   if($mode eq 'cert') {
      $parsed = $self->{'CERT'}->parse_cert($self, $itemname);
   }else{
      $parsed = $self->{'REQ'}->parse_req($self, $itemname);
   }

   defined($parsed) || do {
      if($mode eq 'cert') {
         $self->print_error(gettext("Can't read Certificate"));
      } else {
         $self->print_error(gettext("Can't read Request"));
      }
      return;
   };

   if($mode eq 'cert') {
      # fingerprint in the top of certtextbox
      if(defined($self->{'certfingerprint'})) {
         $self->{'certfingerprint'}->destroy();
      } 
      $self->{'certfingerprint'} = Gtk::Label->new(
            gettext("Fingerprint:")." ".$parsed->{'FINGERPRINT'});
      $self->{'certtextbox'}->pack_start($self->{'certfingerprint'}, 0, 0, 0);
   }

   if($mode eq 'cert') {
      $bottombox  = 'certbottombox';
      $textbox    = 'certtextbox';
      $lefttable  = 'certlefttable';
      $leftbox    = 'certleftbox';
      $righttable = 'certrighttable';
      $rightbox   = 'certrightbox';
   }else{
      $bottombox  = 'reqbottombox';
      $textbox    = 'reqtextbox';
      $lefttable  = 'reqlefttable';
      $leftbox    = 'reqleftbox';
      $righttable = 'reqrighttable';
      $rightbox   = 'reqrightbox';
   }

   # hbox in the bottom
   if(defined($self->{$bottombox})) {
      $self->{$bottombox}->destroy();
   }
   $self->{$bottombox} = Gtk::HBox->new(1, 0);
   $self->{$textbox}->pack_start($self->{$bottombox}, 0, 0, 0);

   # vbox in the bottom/left
   if(defined($self->{$lefttable})) {
      $self->{$lefttable}->destroy();
   }
   @fields = qw( CN EMAIL O OU L ST C);
   $self->{$lefttable} = _create_detail_table($self, \@fields, $parsed);
   $self->{$leftbox} = Gtk::VBox->new(0, 0);
   $self->{$bottombox}->pack_start($self->{$leftbox}, 0, 0, 0);
   $self->{$leftbox}->pack_start($self->{$lefttable}, 0, 0, 0);

   # vbox in the bottom/right
   if(defined($self->{$righttable})) {
      $self->{$righttable}->destroy();
   }
   @fields = qw(STATUS TYPE SERIAL NOTBEFORE NOTAFTER KEYSIZE PK_ALGORITHM
         SIG_ALGORITHM TYPE);

   $self->{$righttable} = _create_detail_table($self, \@fields, $parsed);
   $self->{$rightbox} = Gtk::VBox->new(0, 0);
   $self->{$bottombox}->pack_start($self->{$rightbox}, 0, 0, 0);
   $self->{$rightbox}->pack_start($self->{$righttable}, 0, 0, 0);

   $self->{$textbox}->show_all();
      
   return;
}

#
# create standard label 
#
sub _create_label {
   my ($self, $text, $mode, $wrap, $bold) = @_;

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
      if(defined($self->{'stylebold'})) {
         $label->set_style($self->{'stylebold'});
      }
   }
   
   return($label);
}

#
# create standard dialog box
#
sub _dialog_box {
   my ($self, $title, $text, $button1, $button2) = @_;

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
      my $label = _create_label($self, $text, 'center', 0, 1);
      $box->vbox->pack_start($label, 0, 0, 0);
   }

   return($box);
}

#
# write two labels to table
#
sub _label_to_table {
   my ($self, $key, $val, $table, $row, $mode, $wrap, $bold) = @_;

   my ($label, $entry);

   $label = _create_label($self, $key, $mode, $wrap, $bold);
   $label->set_padding(20, 0);
   $table->attach_defaults($label, 0, 1, $row, $row+1);

   $label = _create_label($self, $val, $mode, $wrap, $bold);
   $label->set_padding(20, 0);
   $table->attach_defaults($label, 1, 2, $row, $row+1);

   $row++;
   $table->resize($row, 2);

   return($row);
}

#
# write label and entry to table
#
sub _entry_to_table {
   my ($self, $text, $var, $table, $row, $vis, $box) = @_;

   my ($label, $entry);

   $label = _create_label($self, $text, 'left', 0, 0);
   $table->attach_defaults($label, 0, 1, $row, $row+1);

   $entry = Gtk::Entry->new();
   $entry->set_text($$var) if(defined($$var));
   $table->attach_defaults($entry, 1, 2, $row, $row+1);
   $entry->signal_connect('changed', \&_entry_to_var, $entry, $var, $box);
   $entry->set_visibility($vis);

   return($entry);
}

#
# fill given var-reference with text from entry
#
sub _entry_to_var {
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
sub _entry_to_var_san {
   my ($widget, $entry, $var, $box, $words, $radio1, $radio2, $radio3) = @_;

   if(defined($words)) {
      $$var = $words->{$entry->get_text()};
      if($$var eq 'user') {
         $radio1->set_sensitive(1) if(defined($radio1));
         $radio2->set_sensitive(1) if(defined($radio2));
         $radio3->set_sensitive(1) if(defined($radio3));
      }elsif($$var eq 'sig'|| $$var eq 'key' || $$var eq 'keysig' ||
             $$var eq 'keyCertSign' || $$var eq 'cRLSign' ||
             $$var eq 'keyCertSign, cRLSign') {
         $radio1->set_sensitive(1) if(defined($radio1));
         $radio2->set_sensitive(1) if(defined($radio2));
         $radio3->set_sensitive(1) if(defined($radio3));
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
sub _toggle_to_var {
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
sub _toggle_to_var_pref {
   my ($button, $var, $value, $box) = @_;

   $$var = $value if($button->active());

   if(defined($box) && defined($box->notebook->cur_page())) {
      $box->set_modified(1);
   }

   return;
}

#
# create standard table with extensions (cert/req)
#
sub _create_extension_table {
   my ($self, $parsed) = @_;

   my ($table, $rows, $key, $val);

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $table->set_col_spacing(0, 10);

   while(($key, $val) = each(%{$parsed->{'EXT'}})) {
      $rows = _label_to_table($self, $key.":", $val->[0], 
            $table, $rows, 'left', 1, 0);
            
      if(@{$val} > 1) {
         for(my $i = 1; $val->[$i]; $i++) { 
            $rows = _label_to_table($self, '', $val->[$i], 
                  $table, $rows, 'left', 1, 0);
         }
      }
   }

   return($table);
}

#
# create standard table with details (cert/req)
#
sub _create_detail_table {
   my ($self, $fields, $parsed) = @_;

   my ($table, $rows, %words);

   %words = ( 'CN'            => gettext("Common Name:"),
              'EMAIL'         => gettext("eMail Address:"),
              'O'             => gettext("Organization:"),
              'OU'            => gettext("Organizational Unit:"),
              'L'             => gettext("Location:"),
              'ST'            => gettext("State:"),
              'C'             => gettext("Country:"),
              'NOTBEFORE'     => gettext("Creation Date:"),
              'NOTAFTER'      => gettext("Expiration Date:"),
              'KEYSIZE'       => gettext("Keylength:"),
              'PK_ALGORITHM'  => gettext("Public Key Algorithm:"),
              'SIG_ALGORITHM' => gettext("Signature Algorithm:"),
              'TYPE'          => gettext("Type:"),
              'SERIAL'        => gettext("Serial:"),
              'STATUS'        => gettext("Status:")
   );

   $rows = 1;
   $table = Gtk::Table->new($rows, 2, 0);
   $table->set_col_spacing(0, 10);

   foreach my $f (@{$fields}) {
      if(defined($parsed->{$f})){
         if(ref($parsed->{$f})) {
            foreach(@{$parsed->{$f}}) {
               $rows = _label_to_table($self, $words{$f}, $_, 
                     $table, $rows, 'left', 0, 0);
            }
         }else{
            $rows = _label_to_table($self, $words{$f}, $parsed->{$f},
                  $table, $rows, 'left', 0, 0);
         }
      }
   }

   return($table);
}

#
# sort the table by the clicked column
#
sub _sort_clist {
   my ($clist, $col) = @_;

   $clist->set_sort_column($col);
   $clist->sort();

   return(1);
}

#
# finished...
#
sub _exit_clean {
   my ($self, $ret) = @_;

   $ret = 0 unless(defined $ret);
   
   Gtk->exit($ret);

   exit($ret);
}

1

# 
# $Log: GUI.pm,v $
# Revision 1.54  2004/05/11 18:33:58  sm
# corrected generation of exportfile names
#
# Revision 1.52  2004/05/06 19:44:53  sm
# new version
#
# Revision 1.51  2004/05/06 19:22:23  sm
# added display and export for DSA and RSA keys
#
# Revision 1.49  2004/05/05 20:59:42  sm
# added configuration for CA
#
# Revision 1.47  2004/05/04 20:34:58  sm
# added patches from Olaf Gellert <og@pre-secure.de> for selecting the Digest
#
# Revision 1.46  2004/05/03 19:54:32  sm
# added CA configuraation tab
#
# Revision 1.42  2003/10/03 11:17:47  sm
# correctly import/show details of requests without x509 extensions
#
# Revision 1.41  2003/10/01 21:36:37  sm
# added critical to gettext()
#
# Revision 1.40  2003/10/01 21:24:30  sm
# changed version to 0.5.4
#
# Revision 1.39  2003/10/01 20:55:23  sm
# changed order of some options
#
# Revision 1.38  2003/10/01 20:51:27  sm
# removed nsCaRevocationUrl from non-CA configuration
#
# Revision 1.37  2003/10/01 20:48:42  sm
# configure nsRenewalUrl and set during signing
#
# Revision 1.36  2003/10/01 19:51:02  sm
# don't show toggle buttons if keyUsage is 'none'
#
# Revision 1.35  2003/10/01 13:57:42  sm
# configure nsRevocationUrl and ask during signing
#
# Revision 1.34  2003/10/01 13:08:30  sm
# removed subjectAltName from standard options
#
# Revision 1.33  2003/10/01 13:04:30  sm
# configure keyUsage for client
#
# Revision 1.32  2003/10/01 13:01:02  sm
# check if propertybox is already created before activating options
#
# Revision 1.31  2003/10/01 12:42:47  sm
# configure subjectAltName for client and ask during signing
#
# Revision 1.30  2003/09/30 20:14:43  sm
# configure nsCertType for client
#
# Revision 1.29  2003/09/30 19:42:31  sm
# configure keyUsage
#
# Revision 1.28  2003/09/29 17:02:39  sm
# configure subjectAltName and set during signing
#
# Revision 1.27  2003/09/28 19:46:45  sm
# configure subjectAltName
#
# Revision 1.26  2003/09/28 19:44:09  sm
# configure subjectAltName
#
# Revision 1.25  2003/09/22 20:23:39  sm
# configure subjectAltName
#
# Revision 1.24  2003/09/22 16:10:38  sm
# version 0.5.3
#
# Revision 1.23  2003/09/22 16:09:42  sm
# removed Typo
#
# Revision 1.22  2003/09/02 19:38:43  sm
# change nsSslServerName when signing
#
# Revision 1.21  2003/09/02 13:54:16  sm
# fixed bug: configuration can't be saved
#
# Revision 1.20  2003/09/02 13:17:27  sm
# added detection of PKCS#10
#
# Revision 1.19  2003/08/28 13:14:46  sm
# added renewal of certificates
#
# Revision 1.18  2003/08/27 21:34:05  sm
# some more errorhandling
#
# Revision 1.17  2003/08/26 17:02:08  sm
# added focus
#
# Revision 1.16  2003/08/26 15:04:08  sm
# tooltips/accelarators
#
# Revision 1.15  2003/08/26 14:02:17  sm
# dynamic width of right mouse menu
#
# Revision 1.14  2003/08/26 13:19:02  sm
# added sorting to clist
#
# Revision 1.13  2003/08/26 13:00:09  sm
# changed some window parameters
#
# Revision 1.12  2003/08/22 20:36:56  sm
# code cleanup
#
# Revision 1.9  2003/08/19 15:48:32  sm
# code cleanup
#
# Revision 1.7  2003/08/17 17:26:19  sm
# added contect menus in lists
#
# Revision 1.5  2003/08/16 22:05:24  sm
# first release with Gtk-Perl
#
# Revision 1.3  2003/08/13 20:38:51  sm
# functionality done
#
# Revision 1.2  2003/08/13 19:39:36  sm
# rewrite for Gtk
#
# Revision 1.20  2003/07/04 23:21:25  sm
# changed version
#
# Revision 1.19  2003/07/04 22:58:58  sm
# first round of the translation is done
#
# Revision 1.18  2003/07/03 20:59:03  sm
# a lot of gettext() inserted
#
# Revision 1.17  2003/07/03 07:30:01  sm
# inserted a lot of gettext()
#
# Revision 1.16  2003/06/30 22:35:30  sm
# changed version
#
# Revision 1.15  2003/06/30 22:33:18  sm
# added conversion of index.txt
#
# Revision 1.14  2003/06/26 23:28:35  sm
# added zip functions
#
# Revision 1.13  2003/06/26 20:44:31  sm
# added zip patch from ludwig.nussel@suse.de
#
# Revision 1.12  2003/06/23 21:31:17  sm
# changed version
#
# Revision 1.11  2003/06/23 21:16:29  sm
# automatically change filename and buttonstatus during export
#
# Revision 1.10  2003/06/23 20:11:29  sm
# some new texts from ludwig.nussel@suse.de
#
# Revision 1.9  2003/06/19 21:46:43  sm
# change button status dynamically
#
# Revision 1.7  2003/06/19 13:52:03  sm
# made default_crl_days configurable and some more usability stuff
#
# Revision 1.4  2002/10/07 17:33:58  sm
# added horizontal scrollbar to listings
# modified some dialogs (open, delete,...)
#
# Revision 1.3  2002/10/04 15:15:46  sm
# increased version
#
# Revision 1.2  2002/09/27 19:54:50  sm
# Increased version
#
# 
