# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: WORDS.pm,v 1.4 2005/02/20 16:02:22 sm Exp $
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
package GUI::WORDS;

use Locale::gettext;

sub new {
   my $that = shift;

   my $self = {
    'none'                  => gettext("Not set"),
    'user'                  => gettext("Ask User"),
    'critical'              => gettext("critical"),
    'noncritical'           => gettext("not critical"),
    'emailcopy'             => gettext("Copy Email"),
    'raw'                   => gettext("raw"),
    'dns'                   => gettext("DNS Name"),
    'ip'                    => gettext("IP Address"),
    'mail'                  => gettext("Email"),
    'server'                => gettext("SSL Server"),
    'server, client'        => gettext("SSL Server, SSL Client"),
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
    'CN'                    => gettext("Common Name"),
    'EMAIL'                 => gettext("eMail Address"),
    'O'                     => gettext("Organization"),
    'OU'                    => gettext("Organizational Unit"),
    'L'                     => gettext("Location"),
    'ST'                    => gettext("State"),
    'C'                     => gettext("Country"),
    'NOTBEFORE'             => gettext("Creation Date"),
    'NOTAFTER'              => gettext("Expiration Date"),
    'KEYSIZE'               => gettext("Keylength"),
    'PK_ALGORITHM'          => gettext("Public Key Algorithm"),
    'SIG_ALGORITHM'         => gettext("Signature Algorithm"),
    'TYPE'                  => gettext("Type"),
    'SERIAL'                => gettext("Serial"),
    'STATUS'                => gettext("Status"),
    'FINGERPRINTMD5'        => gettext("Fingerprint (MD5)"),
    'FINGERPRINTSHA1'       => gettext("Fingerprint (SHA1)"),
    gettext("Not set")                             => 'none',
    gettext("Ask User")                            => 'user',
    gettext("critical")                            => 'critical',
    gettext("not critical")                        => 'noncritical',
    gettext("Copy Email")                          => 'emailcopy',
    gettext("raw")                          => 'raw',
    gettext("DNS Name")                            => 'dns',
    gettext("Email")                               => 'email',
    gettext("IP Address")                          => 'ip',
    gettext("SSL Server")                          => 'server',
    gettext("SSL Server, SSL Client")              => 'server, client',
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
   };

   my $class = ref($that) || $that;

   bless($self, $class);

   $self;
}

1
