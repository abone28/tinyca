# Copyright (c) Olaf Gellert <og@pre-secure.de> and
#               Stephan Martin <sm@sm-zone.net>
#
# $Id: X509_browser.pm,v 1.10 2004/07/15 08:29:37 sm Exp $
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
package GUI::X509_browser;

use HELPERS;
use GUI::HELPERS;
use OpenSSL;
use MIME::Base64;
use GUI::X509_infobox;

#use Gtk;
# will we need this?
#use Gnome;
# init Gtk;        # initialize Gtk-Perl
# Gnome->init('Browser', '0.1');
set_locale Gtk;  # internationalize

use POSIX;
use Locale::gettext;

my $ossldefault="/usr/bin/openssl";
my $tmpdefault="/tmp";

my $version = "0.1";
my $true = 1;
my $false = undef;


sub new {
   my $that = shift;
   my $self = {};
   my $mode = shift;
   my $openssl = shift;
   my $cert    = shift;
   my $req     = shift;
   

   my ($font, $fontfix);

   my $class = ref($that) || $that;

   $self->{'main'} = shift;

   if ((defined $mode) && (($mode eq 'cert') || ($mode eq 'req'))) {
      $self->{'mode'}=$mode;
      }
    else {
      printf STDERR "No mode specified for X509browser\n";
      return undef;
      }

   if (defined $openssl) {
     # printf STDERR "OpenSSL given on init.\n";
     $self->{'OpenSSL'}=$openssl;
     }
   else {
     # printf STDERR "Creating own OpenSSL object.\n";
     $self->{'OpenSSL'}=OpenSSL->new($ossldefault, $tmpdefault);
     }

   if(defined($cert)) {
      $self->{'CERT'} = $cert;
   } else {
      $self->{'CERT'} = CERT->new($self->{'OpenSSL'});
   }

   if(defined($req)) {
      $self->{'REQ'} = $req;
   } else {
      $self->{'REQ'} = REQ->new();
   }

   # initialize fonts and styles
   $font    = Gtk::Gdk::Font->fontset_load("-adobe-helvetica-bold-r-normal--*-120-*-*-*-*-*-*");
   if(defined($font)) {
      $self->{'stylebold'} = Gtk::Style->new();
      $self->{'stylebold'}->font($font);
   } else {
      $self->{'stylebold'} = undef;
   }

   $fontfix = Gtk::Gdk::Font->fontset_load("-adobe-courier-medium-r-normal--*-100-*-*-*-*-*-*");
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

   bless($self, $class);

   $self;
}


sub create_window {
   my ($self, $title, $ok_text, $cancel_text,
	      $ok_function, $cancel_function) = @_;

   my ($button_ok, $button_cancel);

   if ( $self->{'dialog_shown'} == $true ) {
     return(undef);
     }

   # check arguments
   if ($title eq undef) {
     $title = "CA browser, V$version";
     }

   if (not defined($ok_text)) {
     $ok_text = gettext("OK");
     }
   if (not defined($cancel_text)) {
     $cancel_text = gettext("Cancel");
     }

   # initialize main window
   $self->{'window'} = new Gtk::Dialog();

   # $self->{'window'}->set_policy($false,$false,$true);

   # store pointer to vbox as "browser widget"
   $self->{'browser'}=$self->{'window'}->vbox;

   if (defined $ok_function) {
      # todo: we should check if this is a function reference
      $self->{'User_OK_function'} = $ok_function;
      }
   $self->{'OK_function'} = sub { $self->ok_function(); };

   if (defined $cancel_function) {
      # todo: we should check if this is a function reference
      $self->{'User_CANCEL_function'} = $cancel_function;
      }
   $self->{'CANCEL_function'} = sub { $self->cancel_function(); };



   $button_ok = new Gtk::Button( "$ok_text" );
   $button_ok->signal_connect( "clicked", $self->{'OK_function'});
   $self->{'window'}->action_area->pack_start( $button_ok, $true, $true, 0 );

   $button_cancel = new Gtk::Button( "$cancel_text" );
   $button_cancel->signal_connect('clicked', $self->{'CANCEL_function'});
   $self->{'window'}->action_area->pack_start( $button_cancel, $true, $true, 0 );

   $self->{'window'}->set_title( "$title" );

   $self->{'window'}->show_all();

}

sub set_window {
  my $self = shift;
  my $widget = shift;

  if ( (not defined $self->{'browser'}) || ( $self->{'browser'} == undef )) {
    $self->{'browser'}=$widget;
  } else {
    # browser widget already exists
    return $false;
  }
}

sub set_contextfunc {
  my ($self, $context_function, $event, $referrer, @args) = @_;

    $self->{'x509clist'}->signal_connect($event, 
            $context_function, $referrer, @args);
}

sub destroy_window {
  my $self=shift;

  if (defined $self->{'window'}) {
    $self->{'window'}->destroy();
    return $true;
    }
  else {
    return $false;
  }
}

sub add_ca_select {
  my $self = shift;
  my $directory = shift;
  my $CAref = shift;
  my $active = shift;

  my ($option_menu, $option_popup, $count, $menu_item, @CAs, $active_index,
      $caselect_win, $caselect_box, $gtktemp, $subdir);

  if ($self->{'mode'} eq "cert") {
    $subdir = "certs";
    }
  elsif ($self->{'mode'} eq "req") {
    $subdir = "req";
    }
  else {
    # unknown mode
    return $false;
    }

  if ($CAref == undef) {
    return $false;
    }

  @CAs=@$CAref;
  $self->{'CAlist'}=\@CAs;
  $self->{'actca'}=$active;

  if ($self->{'ca_select'} == undef) {
    $caselect_box=new Gtk::HBox(0,4);
    $self->{'browser'}->pack_start($caselect_box, 0, 1, 0);

    $gtktemp=Gtk::Label->new(gettext("Choose CA:"));
    $caselect_box->pack_start($gtktemp, 0, 1, 0);
    
    $option_menu=new Gtk::OptionMenu();
    $option_popup=new Gtk::Menu();

    for ($count=0; $count<=$#CAs; $count++) {
      # printf STDERR "adding item %s\n", $CAs[$count];
      $menu_item=new Gtk::MenuItem($CAs[$count]);

      if ((defined $active) && ($active eq $CAs[$count])) {
	$active_index=$count;
        }
      $option_popup->append($menu_item);
      $menu_item->signal_connect('activate',
         sub { $self->add_list ($_[1], $_[2], $_[3], $_[4]) },
                         $active,
			 $directory."/".$CAs[$count]."/".$subdir,
      			 $directory."/".$CAs[$count]."/crl/crl.pem",
      			 $directory."/".$CAs[$count]."/index.txt");
      }
    $option_menu->set_menu( $option_popup );
    if (not defined $active) {
      # printf STDERR "default selection of item 0\n";
      $option_menu->set_history(0);
      }
    else {
      $option_menu->set_history($active_index);
      }
    $caselect_box->pack_start($option_menu, 1, 1, 0);
    $caselect_box->show();
    # $self->{'browser'}->show_all();
  } else {
    return $false;
  } 

}

sub add_list {
   my ($self, $actca, $directory, $crlfile, $indexfile) = @_;

   my ($x509listwin, $mode, @certtitles, @reqtitles, $ind);

   # printf STDERR "AddList: Self: $self, Dir $directory, CRL $crlfile, Index: $indexfile\n";

   @certtitles = (gettext("Common Name"),
         gettext("eMail Address"),
         gettext("Organizational Unit"),
         gettext("Organization"),
         gettext("Location"),
         gettext("State"),
         gettext("Country"), 
         gettext("Status"),
         "index");

   @reqtitles = (gettext("Common Name"),
         gettext("eMail Address"),
         gettext("Organizational Unit"),
         gettext("Organization"),
         gettext("Location"),
         gettext("State"),
         gettext("Country"), 
         "index");

  $self->{'actca'}=$actca;
  $self->{'actdir'}=$directory;
  $self->{'actcrl'}=$crlfile;
  $self->{'actindex'}=$indexfile;
  $mode=$self->{'mode'};

  if(defined($self->{'x509box'})) {
    $self->{'browser'}->remove($self->{'x509box'});
    $self->{'x509box'}->destroy();
  }

  # should we display certificates?
  if ((defined $mode) && ($mode eq "cert")) {

    $self->{'x509box'} = Gtk::VBox->new(0, 0);
    # pane for list (top) and cert infos (bottom)
    $self->{'x509pane'} = Gtk::VPaned->new();
    $self->{'x509pane'}->set_handle_size(10);
    $self->{'x509pane'}->set_gutter_size(8);
    $self->{'x509pane'}->set_position(250);
    $self->{'x509box'}->add($self->{'x509pane'});

    $self->{'browser'}->pack_start($self->{'x509box'}, 1, 1, 0);

    # now the list
    $x509listwin = Gtk::ScrolledWindow->new(undef, undef);
    $x509listwin->set_policy('automatic', 'automatic');
    $self->{'x509pane'}->pack1($x509listwin, 1, 1);
      
    $self->{'x509clist'} = Gtk::CList->new_with_titles(@certtitles);
    # printf STDERR "Self: $self  CertCList: $self->{'x509clist'}\n";
    $self->{'x509clist'}->set_sort_column (0);
    $self->{'x509clist'}->signal_connect('click_column', \&_sort_clist);

    for(my $i = 0; $i < 7; $i++) {
       $self->{'x509clist'}->set_column_auto_resize ($i, 1);
       }
    $self->{'x509clist'}->signal_connect('select_row', 
            \&_fill_info, $self, 'cert' );
    $self->{'x509clist'}->set_column_visibility(8, 0);
    $x509listwin->add($self->{'x509clist'});

    update($self, $directory, $crlfile, $indexfile, $true);
  }

  # or should we display requests?
  elsif ((defined $mode) && ($mode eq "req")) {
    $self->{'x509box'} = Gtk::VBox->new(0, 0);
    # pane for list (top) and request infos (bottom)
    $self->{'x509pane'} = Gtk::VPaned->new();
    $self->{'x509pane'}->set_handle_size(10);
    $self->{'x509pane'}->set_gutter_size(8);
    $self->{'x509pane'}->set_position(280);
    $self->{'x509box'}->add($self->{'x509pane'});

    $self->{'browser'}->add($self->{'x509box'});

    # now the list
    $x509listwin = Gtk::ScrolledWindow->new(undef, undef);
    $x509listwin->set_policy('automatic', 'automatic');
    $self->{'x509pane'}->pack1($x509listwin, 1, 1);
      
    $self->{'x509clist'} = Gtk::CList->new_with_titles(@reqtitles);
    # printf STDERR "Self: $self  X509CList: $self->{'x509clist'}\n";
    $self->{'x509clist'}->set_sort_column (0);
    $self->{'x509clist'}->signal_connect('click_column', \&_sort_clist);

    for(my $i = 0; $i < 6; $i++) {
       $self->{'x509clist'}->set_column_auto_resize ($i, 1);
       }
    $self->{'x509clist'}->signal_connect('select_row', 
            \&_fill_info, $self, 'req' );
    $self->{'x509clist'}->set_column_visibility(7, 0);
    $x509listwin->add($self->{'x509clist'});

    update($self, $directory, $crlfile, $indexfile, $true);

    }
  else {
    # undefined mode (not cert, not req) -> do nothing
    return undef;
    }

}


sub update {
  my ($self, $directory, $crlfile, $indexfile, $force) = @_;

  $self->{'actdir'}=$directory;
  $self->{'actcrl'}=$crlfile;
  $self->{'actindex'}=$indexfile;

  if ($self->{'mode'} eq "cert") {
    update_cert($self, $directory, $crlfile, $indexfile, $force);
    }
  elsif ($self->{'mode'} eq "req") {
    update_req($self, $directory, $crlfile, $indexfile, $force);
    }
  else {
    return undef;
    }

  if ((defined $self->{'infowin'}) && ($self->{'infowin'} ne "")) {
    # $self->{'infowin'}->hide();
    # undef $self->{'infowin'};
    # add_info($self);
    update_info($self);
    }


  $self->{'browser'}->show_all();
  return $true;
}


sub update_req {
    my ($self, $directory, $crlfile, $indexfile, $force) = @_;

    my ($ind);

    $self->{'REQ'}->read_reqlist($directory, $crlfile, $indexfile, $force,
          $self->{'main'});

    $self->{'x509clist'}->clear();

     $ind = 0;
     foreach my $n (@{$self->{'REQ'}->{'reqlist'}}) {
       my ($name, $state) = split(/\%/, $n);
       my @line = split(/\:/, $name);
       my $row = $self->{'x509clist'}->append(@line);
       $self->{'x509clist'}->set_text($row, 7, $ind);
       $ind++;
       }
     # now select the first row to display certificate informations
     $self->{'x509clist'}->select_row(0, 0);

}

sub update_cert {
    my ($self, $directory, $crlfile, $indexfile, $force) = @_;

    my ($ind);

    $self->{'CERT'}->read_certlist($directory, $crlfile, $indexfile, $force,
          $self->{'main'});

    $self->{'x509clist'}->clear();

     $ind = 0;
     foreach my $n (@{$self->{'CERT'}->{'certlist'}}) {
       my ($name, $state) = split(/\%/, $n);
       my @line = split(/\:/, $name);
       my $row = $self->{'x509clist'}->append(@line);
       $self->{'x509clist'}->set_text($row, 7, $state);
       if($state eq gettext("VALID")) {
         $self->{'x509clist'}->set_cell_style($row, 7, $self->{'stylegreen'});
         }
       else {
         $self->{'x509clist'}->set_cell_style($row, 7, $self->{'stylered'});
         }
       $self->{'x509clist'}->set_text($row, 8, $ind);
       $ind++;
       }
     # now select the first row to display certificate informations
     $self->{'x509clist'}->select_row(0, 0);
}

sub update_info {
    my ($self)=@_;

    my ($title, $parsed, $itemname, $dn);

    $itemname=selection_fname($self);
    $dn=selection_dn($self);

    if (defined $itemname) {
      if ($self->{'mode'} eq 'cert') {
        $parsed=$self->{'OpenSSL'}->parsecert(
		$self->{'actcrl'},
		$self->{'actindex'},
		$itemname,
		$false);
        $title = gettext("Certificate Information");
        }
      else {
        $parsed=$self->{'OpenSSL'}->parsereq(
		$self->{'actconfig'},
		$itemname);
        $title = gettext("Request Information");
        }

    defined($parsed) || GUI::HELPERS::print_error(gettext("Can't read file"));

    if(not defined($self->{'infobox'})) {
       $self->{'infobox'}=Gtk::VBox->new();
    }

    # printf STDERR "DEBUG: Infowin: $self->{'infowin'}, infobox: $self->{'infobox'}\n";
    $self->{'infowin'}->display($self->{'infobox'}, $parsed,
	$self->{'mode'}, $title);

    }
  else {
    # nothing selected
    $self->{'infowin'}->hide();
    }
}

#
# add infobox to the browser window
#
sub add_info {
  my $self = shift;

  my ($row, $index, $parsed, $title, $cert, $status, $certname, $list);

  if ((defined $self->{'infowin'}) && ($self->{'infowin'} ne "")) { 
     $self->{'infowin'}->hide();
  } else { 
     $self->{'infowin'} = GUI::X509_infobox->new();
  }

  # printf STDERR "Infowin: $self->{'infowin'}\n";
  # printf STDERR "x509clist: $self->{'x509clist'}\n";

  $row=$self->{'x509clist'}->selection();
  if(defined($row)) { 
     if ($self->{'mode'} eq 'cert') { 
        $index=$self->{'x509clist'}->get_text($row, 8);
        $list = $self->{'CERT'}->{'certlist'};
     } else { 
        $index=$self->{'x509clist'}->get_text($row, 7); 
        $list = $self->{'REQ'}->{'reqlist'};
     }
  }

  if (defined $index) {
    ($cert, $status) = split(/\%/, $list->[$index]);
    $certname=$cert;
    $certname= MIME::Base64::encode($cert, '');
    $certname=$self->{'actdir'}."/$certname".".pem";
    if ($self->{'mode'} eq 'cert') {
      $parsed=$self->{'OpenSSL'}->parsecert(
		$self->{'actcrl'},
		$self->{'actindex'},
		$certname,
		$false);
      $title="Certificate Information";
      }
    else {
      $parsed=$self->{'OpenSSL'}->parsereq(
		$self->{'actconfig'},
		$certname);
      $title="Request Information";
      }

    defined($parsed) || GUI::HELPERS::print_error(gettext("Can't read file"));

    # printf STDERR "Infowin: $self->{'infowin'}\n";
    $self->{'infobox'}=Gtk::VBox->new();
    $self->{'x509pane'}->pack2($self->{'infobox'}, 1, 1);
    $self->{'infowin'}->display($self->{'infobox'}, $parsed, $self->{'mode'},
          $title);
  }
}

sub hide {
  my ($self) = @_;

  $self->{'window'}->hide();
  $self->{'dialog_shown'} = $false;
}

sub destroy {
  my ($self) = @_;

  $self->{'window'}->destroy();
  $self->{'dialog_shown'} = $false;
}

#
# signal handler for selected list items
# (updates the X509_infobox window) 
#
sub _fill_info {
   my ($clist, $self, $mode, $row, $column) = @_;

   my ($index, $item, $status, $itemname, $parsed, $title, $list, $t);

  # printf STDERR "Fill_Info: @_\n";

  if (defined $self->{'infowin'}) {

   if($mode eq 'cert') {
      $index = $clist->get_text($row, 8);
      $list =  $self->{'CERT'}->{'certlist'};
   }elsif($mode eq 'req') {
      $index = $clist->get_text($row, 7);
      $list = $self->{'REQ'}->{'reqlist'};
   }else {
         $t = sprintf(gettext("Invalid mode for: _fill_info(): %s"), $mode);
         GUI::HELPERS::print_error($t);
      return;
   }

  if (defined $index) {
    ($item, $status) = split(/\%/, $list->[$index]);
    $itemname= MIME::Base64::encode($item, '');
    # $itemname=$item;
    $itemname=$self->{'actdir'}."/$itemname".".pem";
    # printf STDERR "Itemname: $itemname\n";
    update_info($self);
    
    }

  }

}

sub selection_fname {
  my $self = shift;

  my ($selected, $row, $index, $dn, $status, $filename, $mode, $list);

  $row   = $self->{'x509clist'}->selection();
  if (not defined $row) {
    return undef;
    }

  $mode=$self->{'mode'};
  if ($mode eq 'req') {
    $index = $self->{'x509clist'}->get_text($row, 7);
    $list = $self->{'REQ'}->{'reqlist'};
    }
  elsif ($mode eq 'cert') {
    $index = $self->{'x509clist'}->get_text($row, 8);
    $list = $self->{'CERT'}->{'certlist'};
    }
  else {
    GUI::HELPERS::print_error(
           gettext("Invalid browser mode for selection_dn():"." ".$mode));
    }


  if (defined $index) {
    ($dn, $status) = split(/\%/, $list->[$index]);
    $filename= MIME::Base64::encode($dn, '');
    $filename=$self->{'actdir'}."/$filename".".pem";
    }
  else {
    $filename = undef;
    }

  return($filename);
}

sub selection_dn {
  my $self = shift;

  my ($selected, $row, $index, $dn, $status, $mode, $list);

  $row   = $self->{'x509clist'}->selection();
  if (not defined $row) {
    return undef;
    }

  $mode=$self->{'mode'};
  if ($mode eq 'req') {
    $index = $self->{'x509clist'}->get_text($row, 7);
    $list  = $self->{'REQ'}->{'reqlist'};
    }
  elsif ($mode eq 'cert') {
    $index = $self->{'x509clist'}->get_text($row, 8);
    $list  = $self->{'CERT'}->{'certlist'};
    }
  else {
    GUI::HELPERS::print_error(
           gettext("Invalid browser mode for selection_dn():"." ".$mode));
    }

  if (defined $index) {
    ($dn, $status) = split(/\%/, $list->[$index]);
    }
  else {
    $dn = undef;
    }
  return($dn);
}

sub selection_cadir {
  my $self = shift;

  my ($selected, $dir);

  $dir   = $self->{'actdir'};
  # cut off the last directory name to provide the ca-directory
  $dir =~ s/\/certs$//;
  $dir =~ s/\/req$//;
  return($dir);
}


sub selection_caname {
  my $self = shift;

  my ($selected, $caname);

  $caname   = $self->{'actca'};
  return($caname);
}

sub selection_cn {
  my $self = shift;

  my ($selected, $row, $index, $cn, $mode);

  $row   = $self->{'x509clist'}->selection();
  if (not defined $row) {
    return undef;
    }

  $mode=$self->{'mode'};
  if (($mode eq 'req') || ($mode eq 'cert')) {
    $cn = $self->{'x509clist'}->get_text($row, 0);
    }
  else {
    GUI::HELPERS::print_error(
           gettext("Invalid browser mode for selection_cn():"." ".$mode));
    }

  return($cn);
}

sub selection_email {
  my $self = shift;

  my ($selected, $row, $index, $email, $mode);

  $row   = $self->{'x509clist'}->selection();
  if (not defined $row) {
    return undef;
    }

  $mode=$self->{'mode'};
  if (($mode eq 'req') || ($mode eq 'cert')) {
    $email = $self->{'x509clist'}->get_text($row, 1);
    }
  else {
    GUI::HELPERS::print_error(
           gettext("Invalid browser mode for selection_cn():"." ".$mode));
    }

  return($email);
}


sub selection_status {
  my $self = shift;

  my ($selected, $row, $index, $dn, $status, $mode, $list);

  $row   = $self->{'x509clist'}->selection();
  if (not defined $row) {
    return undef;
    }

  $mode=$self->{'mode'};
  if ($mode eq 'req') {
    $index = $self->{'x509clist'}->get_text($row, 7);
    $list  = $self->{'REQ'}->{'reqlist'};
    }
  elsif ($mode eq 'cert') {
    $index = $self->{'x509clist'}->get_text($row, 8);
    $list  = $self->{'CERT'}->{'certlist'};
    }
  else {
    GUI::HELPERS::print_error(
           gettext("Invalid browser mode for selection_status():"." ".$mode));
    }

  if (defined $index) {
    ($dn, $status) = split(/\%/, $list->[$index]);
    }
  else {
    $status = undef;
    }
  return($status);
}


sub ok_function {
  my ($self) = @_;

  # is there a user defined ok_function?
  if (defined $self->{'User_OK_function'}) {
    $self->{'User_OK_function'}($self, selection_fname($self));
    }
  # otherwise do default
  else {
    printf STDOUT "%s\n", selection_fname($self);
    $self->hide();
    }
  return $true;
  
}

sub cancel_function {
  my ($self) = @_;

  # is there a user defined ok_function?
  if (defined $self->{'User_CANCEL_function'}) {
    $self->{'User_CANCEL_function'}($self, get_listselect($self));
    }
  # otherwise do default
  else {
    $self->{'window'}->hide();
    $self->{'dialog_shown'} = $false;
    }
  return $true;
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
# called on mouseclick in certlist
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
 
$true;


__END__

=head1 NAME

GUI::X509_browser - Perl-Gtk browser for X.509 certificates and requests

=head1 SYNOPSIS

    use X509_browser;

    $browser=X509_browser->new($mode);
    $browser->create_window($title, $oktext, $canceltext,
                            \&okayfunction, \&cancelfunction);
    $browser->add_ca_select($cadir, @calist, $active-ca);
    $browser->add_list($active-ca, $X509dir, $crlfile, $indexfile);
    $browser->add_info();
    my $selection = $browser->selection_fname();
    $browser->hide();

=head1 DESCRIPTION

This displays a browser for X.509v3 certificates or certification
requests (CSR) from a CA managed by TinyCA (or some similar
structure).

Creation of an X509_browser is done by calling B<new()>,
the argument has to be 'cert' or 'req' to display certificates
or requests.

A window can be created for this purpose using
B<create_window($title, $oktext, $canceltext, \&okfunction, \&cancelfunction)>,
all arguments are optional.

=over 1

=item $title:

the existing Gtk::VBox inside which the info will be
displayed.

=item $oktext:

The text to be displayed on the OK button of the dialog.

=item $canceltext:

The text to be displayed on the CANCEL button of the dialog.

=item \&okfunction:

Reference to a function that is executed on click on OK button.
This function should fetch the selected result (using
B<selection_fname()>) and also close the dialog using B<hide()>.

=item \&cancelfunction:

Reference to a function that is executed on click on CANCEL button.
This function should also close the dialog using B<hide()>.

=back

Further functions to get information about the selected item
exist, these are <B>selection_dn()</B>, <B>selection_status()</B>,
<B>selection_cadir()</B> and <B>selection_caname()</B>.

An existing infobox that already displays the content
of some directory can be modified by calling
<B>update()</B> with the same arguments that add_list().

An existing infobox is destroyed by calling B<destroy()>.

=cut
