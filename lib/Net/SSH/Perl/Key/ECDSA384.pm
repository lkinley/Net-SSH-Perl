package Net::SSH::Perl::Key::ECDSA384;
use strict;
use warnings;

use base qw( Net::SSH::Perl::Key::ECDSA );

sub ssh_name { 'ecdsa-sha2-nistp384' }

sub digest { 'SHA384' }

sub siglen { 48 }

1;
