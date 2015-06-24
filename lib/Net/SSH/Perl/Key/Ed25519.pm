package Net::SSH::Perl::Key::Ed25519;
use strict;

use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Constants qw( SSH_COMPAT_BUG_SIGBLOB );
use Net::SSH::Perl::Util qw( :ssh2mp );
use Crypt::Digest::SHA512 qw( sha512 );

use Net::SSH::Perl::Key;
use base qw( Net::SSH::Perl::Key );

use MIME::Base64;
use Crypt::Ed25519;
use Carp qw( croak );

use constant MARK_BEGIN => "-----BEGIN OPENSSH PRIVATE KEY-----\n";
use constant MARK_END   => "-----END OPENSSH PRIVATE KEY-----\n";
use constant AUTH_MAGIC => "openssh-key-v1\0";
use constant ED25519_SK_SZ => 64;
use constant ED25519_PK_SZ => 32;
use constant SALT_LEN => 16;
use constant DEFAULT_ROUNDS => 16;
use constant DEFAULT_CIPHERNAME => 'aes256-cbc';
use constant KDFNAME => 'bcrypt';

sub ssh_name { 'ssh-ed25519' }

sub init {
    my $key = shift;
    my($blob) = @_;

    if ($blob) {
        my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
        $b->append($blob);
        my $ktype = $b->get_str;
        croak __PACKAGE__, "->init: cannot handle type '$ktype'"
            unless $ktype eq $key->ssh_name;
        $key->{pub} = $b->get_str;
    }
}

sub keygen {
    my $class = shift;
    my $key = $class->new(undef);
    $key->{comment} = shift;
    ($key->{pub},$key->{priv}) = Crypt::Ed25519::generate_keypair;
    $key;
}

sub read_private {
    my $class = shift;
    my($key_file, $passphrase) = @_;

    local *FH;
    open FH, $key_file or return;
    my $content = do { local $/; <FH> };
    close FH;
    my $blob = decode_base64(substr($content,length(MARK_BEGIN),
        length($content)-length(MARK_END)-length(MARK_BEGIN)));
    my $str = AUTH_MAGIC;
    croak "Invalid key format" unless $blob =~ /^${str}/;

    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->append($blob);
    $b->consume(length(AUTH_MAGIC));

    my $ciphername = $b->get_str;
    my $kdfname = $b->get_str;
    my $kdfoptions = $b->get_str;
    my $nkeys = $b->get_int32;
    my $pub_key = $b->get_str;
    my $encrypted = $b->get_str;

    croak 'Wrong passphrase'
        if !$passphrase && $ciphername ne 'none';

    croak 'Unknown cipher'
        if $kdfname ne 'none' && $kdfname ne KDFNAME;

    croak 'Invalid format'
        if $kdfname ne 'none' && $ciphername eq 'none';

    croak 'Invalid format: nkeys > 1'
        if $nkeys != 1;

    my $decrypted;
    if ($ciphername eq 'none') {
        $decrypted = $encrypted;
    } else {
        if ($kdfname eq KDFNAME) {
            use Net::SSH::Perl::Cipher;
            my $cipher = eval { Net::SSH::Perl::Cipher->new($ciphername) };
            croak "Cannot load cipher $ciphername" unless $cipher;
            croak 'Invalid format'
                if length($encrypted) < $cipher->blocksize ||
                   length($encrypted) % $cipher->blocksize;

            my $keylen = $cipher->keysize;
            my $ivlen = $cipher->ivlen;
            my $authlen = $cipher->authlen;
            my $tag = $b->bytes($b->offset,$authlen);
            croak 'Invalid format'
                if length($tag) != $authlen;

            $b->empty;
            $b->append($kdfoptions);
            my $salt = $b->get_str;
            croak "Invalid format"
                if length($salt) != SALT_LEN;
            my $rounds = $b->get_int32;

            my $km = bcrypt_pbkdf($passphrase, $salt, $keylen+$ivlen, $rounds);
            my $key = substr($km,0,$keylen);
            my $iv = substr($km,$keylen,$ivlen);
            $cipher->init($key,$iv);
            $decrypted = $cipher->decrypt($encrypted . $tag);
        }
    }

    $b->empty;
    $b->append($decrypted);
    my $check1 = $b->get_int32;
    my $check2 = $b->get_int32;
    croak 'Wrong passphrase (check mismatch)'
        if $check1 != $check2 || ! defined $check1;

    my $type = $b->get_str;
    croak 'Wrong key type'
        unless $type eq $class->ssh_name;
    $pub_key = $b->get_str;
    my $priv_key = $b->get_str;
    croak 'Invalid format'
        if length($pub_key) != ED25519_PK_SZ ||
           length($priv_key) != ED25519_SK_SZ;
    my $comment = $b->get_str;

    # check padding
    my $padnum = 0;
    while ($b->offset < $b->length) {
        croak "Invalid format"
            if ord($b->get_char) != ++$padnum;
    }

    my $key = $class->new(undef);
    $key->{comment} = $comment;
    $key->{pub} = $pub_key;
    $key->{priv} = $priv_key;
    $key;
}

sub write_private {
    my $key = shift;
    my($key_file, $passphrase, $ciphername, $rounds) = @_;
    my ($kdfoptions, $kdfname, $blocksize, $cipher);

    if ($passphrase) {
        $ciphername ||= DEFAULT_CIPHERNAME;
        use Net::SSH::Perl::Cipher;
        $cipher = eval { Net::SSH::Perl::Cipher->new($ciphername) };
        croak "Cannot load cipher $ciphername"
            unless $cipher;

        # cipher init params
        $kdfname = KDFNAME;
        $blocksize = $cipher->blocksize;
        my $keylen = $cipher->keysize;
        my $ivlen = $cipher->ivlen;
        $rounds ||= DEFAULT_ROUNDS;
        use BSD::arc4random;
        my $salt = BSD::arc4random::arc4random_bytes(SALT_LEN);

        my $kdf = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
        $kdf->put_str($salt);
        $kdf->put_int32($rounds);
        $kdfoptions = $kdf->bytes;

        # get key material
        my $km = bcrypt_pbkdf($passphrase, $salt, $keylen+$ivlen, $rounds);
        my $key = substr($km,0,$keylen);
        my $iv = substr($km,$keylen,$ivlen);
        $cipher->init($key,$iv);
    } else {
        $ciphername = 'none';
        $kdfname = 'none';
        $blocksize = 8;
}
    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->put_char(AUTH_MAGIC);
    $b->put_str($ciphername);
    $b->put_str($kdfname);
    $b->put_str($kdfoptions);
    $b->put_int32(1); # one key

    # public key
    my $pub = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $pub->put_str($key->ssh_name);
    $pub->put_str($key->{pub});
    $b->put_str($pub->bytes);

    # create private key blob
    my $kb = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    my $checkint = int(rand(0xffffffff));
    $kb->put_int32($checkint);
    $kb->put_int32($checkint);
    $kb->put_str($key->ssh_name);
    $kb->put_str($key->{pub});
    $kb->put_str($key->{priv});
    $kb->put_str($key->{comment});
    if (my $r = length($kb->bytes) % $blocksize) {
         $kb->put_char(chr($_)) foreach (1..$blocksize-$r);
    }
    my $bytes = $cipher ? $cipher->encrypt($kb->bytes) : $kb->bytes;
    my $tag;
    if (my $authlen = $cipher->authlen) {
        $tag = substr($bytes,-$authlen,$authlen,'');
    }
    $b->put_str($bytes);
    $b->put_chars($tag);

    local *FH;
    open FH, ">$key_file" or die "Cannot write key file";
    print FH MARK_BEGIN;
    print FH encode_base64($b->bytes); 
    print FH MARK_END;
    close FH;
}

sub dump_public { $_[0]->ssh_name . ' ' . encode_base64( $_[0]->as_blob, '') .
                  ' ' . $_[0]->{comment} }

sub sign {
    my $key = shift;
    my $data = shift;
    my $sig = Crypt::Ed25519::sign($data, $key->{pub}, $key->{priv});

    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->put_str($key->ssh_name);
    $b->put_str($sig);
    $b->bytes;
}

sub verify {
    my $key = shift;
    my($signature, $data) = @_;
    my $sigblob;

    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->append($signature);
    my $ktype = $b->get_str;
    croak "Can't verify type ", $ktype unless $ktype eq $key->ssh_name;
    $sigblob = $b->get_str;
    croak "Invalid format" unless length($sigblob) == 64;

    Crypt::Ed25519::verify($data,$key->{pub},$sigblob);
}

sub equal {
    my($keyA, $keyB) = @_;
    $keyA->{pub} && $keyB->{pub} &&
    $keyA->{pub} == $keyB->{pub};
}

sub as_blob {
    my $key = shift;
    my $b = Net::SSH::Perl::Buffer->new( MP => 'SSH2' );
    $b->put_str($key->ssh_name);
    $b->put_str($key->{pub});
    $b->bytes;
}

sub fingerprint_raw { $_[0]->as_blob }

sub bcrypt_hash {
    my ($sha2pass, $sha2salt) = @_;
    my $ciphertext = 'OxychromaticBlowfishSwatDynamite';

    require Crypt::OpenBSD::Blowfish;
    my $bf = Crypt::OpenBSD::Blowfish->new();
    $bf->expandstate($sha2salt,$sha2pass);
    for (my $i=0; $i<64; $i++) {
        $bf->expand0state($sha2salt);
        $bf->expand0state($sha2pass);
    }
    # iterate 64 times
    $bf->encrypt_iterate($ciphertext,64);
}

sub bcrypt_pbkdf {
    my ($pass, $salt, $keylen, $rounds) = @_;
    my $out;
    use constant BCRYPT_HASHSIZE => 32;
    my $key = "\0" x $keylen;
    my $origkeylen = $keylen;

    return if $rounds < 1;
    return unless $pass && $salt;

    my $stride = int(($keylen + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE);
    my $amt = int(($keylen + $stride - 1) / $stride);

    my $sha2pass = sha512($pass);

    for (my $count = 1; $keylen > 1; $count++) {
        my $countsalt = pack('N',$count & 0xffffffff);
        # first round, salt is salt
        my $sha2salt = sha512($salt . $countsalt);

        my $tmpout = $out = bcrypt_hash($sha2pass, $sha2salt);

        for (my $i=1; $i < $rounds; $i++) {
            # subsequent rounds, salt is previous output
            $sha2salt = sha512($tmpout);
            $tmpout = bcrypt_hash($sha2pass,$sha2salt);
            $out ^= $tmpout;
        }

        # pbkdf2 deviation: output the key material non-linearly.
        $amt = $amt<$keylen ? $amt : $keylen;
        my $i;
        for ($i=0; $i<$amt; $i++) {
            my $dest = $i * $stride + ($count - 1);
            last if $dest >= $origkeylen;
            substr($key,$dest,1,substr($out,$i,1));
        }
        $keylen -= $i;
    }
    return $key;
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Key::Ed25519 - Ed25519 key object

=head1 SYNOPSIS

    use Net::SSH::Perl::Key;
    my $key = Net::SSH::Perl::Key->new('Ed25519');

=head1 DESCRIPTION

I<Net::SSH::Perl::Key::Ed25519> subclasses I<Net::SSH::Perl::Key>
to implement an OpenSSH key object.  It uses the Crypt::Ed25519
module to do the crypto heavy liftign.  The I<Net::SSH::Perl::Buffer>
class is used to create blobs and transforms those it into a key 
object and to write keys to an openssh-key-v1 file.

=head1 USAGE

I<Net::SSH::Perl::Key::Ed25519> implements the interface described in
the documentation for I<Net::SSH::Perl::Key>. Any differences or
additions are described here.

=head2 $key->sign($data)

Uses I<Crypt::Ed25519> to sign I<$data> using the private and public
key portions of I<$key>, then encodes that signature into an
SSH-compatible signature blob.

Returns the signature blob.

=head2 $key->verify($signature, $data)

Given a signature blob I<$signature> and the original signed data
I<$data>, attempts to verify the signature using the public key
portion of I<$key>. This uses I<Crypt::Ed25519::verify> to
perform the core verification.

I<$signature> should be an SSH-compatible signature blob, as
returned from I<sign>; I<$data> should be a string of data, as
passed to I<sign>.

Returns true if the verification succeeds, false otherwise.

=head2 Net::SSH::Perl::Key::Ed25519->keygen($comment)

Uses I<Crypt::Ed25519> to generate a new key with comment.

=head1 AUTHOR & COPYRIGHTS

Lance Kinley E<lkinley@loyaltymethods.com>

Copyright (c) 2015 Loyalty Methods, Inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
