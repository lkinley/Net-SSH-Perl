#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

use strict;
use warnings;

use Test::More;

use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Key;

my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
$b->put_str('ssh-rsa'),
$b->put_str("x" x 8);   # Fake key part
$b->put_str("x" x 64);  # Fake key part
my $blob = $b->bytes;

my $res = eval { Net::SSH::Perl::Key->new_from_blob($blob); };
ok(defined($res), 'ssh-rsa key blob works');

$b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
$b->put_str('foo-bar-invalid-name'),
$b->put_str("x" x 8);   # Fake key part
$b->put_str("x" x 64);  # Fake key part
$blob = $b->bytes;

$res = eval { Net::SSH::Perl::Key->new_from_blob($blob); };
my $error = $@;
ok(!defined($res), 'did not create invalid key object');
unlike($error, qr/Can't locate/s, 'did not attempt to load invalid class');
like($error, qr/Unexpected key type provided/s, 'did die with a nicer error');
print $error, "\n";

done_testing;

1;


