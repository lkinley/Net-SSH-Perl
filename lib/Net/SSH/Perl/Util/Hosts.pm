# $Id: Hosts.pm,v 1.10 2008/10/21 15:41:02 turnstep Exp $

package Net::SSH::Perl::Util::Hosts;
use strict;
use warnings;

use Net::SSH::Perl::Constants qw( :hosts );
use Crypt::Misc qw( encode_b64 decode_b64 );
use Crypt::Mac::HMAC qw( hmac );

use Carp qw( croak );

use constant SALT_LEN => 20;

sub _check_host_in_hostfile {
    my($host, $hostfile, $key) = @_;
    my $key_class = ref($key);

    # ssh returns HOST_NEW if the host file can't be opened
    open my $fh, '<', $hostfile or return HOST_NEW;
    local($_, $/);
    $/ = "\n";
    my ($status, $match, $hosts) = (HOST_NEW);
    my $hashmodules = 0;
    while (<$fh>) {
        chomp;
        my ($hosts, $keyblob) = split /\s+/, $_, 2;
        my $fkey;
        ## Trap errors for unsupported key types (eg. if
        ## known_hosts has an entry for an ssh-rsa key, and
        ## we don't have Crypt::RSA installed).
        eval {
            $fkey = $key_class->extract_public($keyblob);
        };
        next if $@;

        my $checkhost = $host;

        ## Check for hashed entries
        if (index($hosts, '|') == 0) {
            if ($hosts !~ /^\|1\|(.+?)\|/) {
                warn qq{Cannot parse line $. of $hostfile\n};
                next;
            }
            my $salt = $1;

            my $rawsalt = decode_b64($salt);
            my $hash = encode_b64(hmac('SHA1',$rawsalt,$host));
            $checkhost = "|1|$salt|$hash";
        }

        for my $h (split /,/, $hosts) {
            if ($h eq $checkhost) {
                if ($key->equal($fkey)) {
                    close $fh or warn qq{Could not close "$hostfile": $!\n};
                    return HOST_OK;
                }
                $status = HOST_CHANGED;
            }
        }
    }
    $status;
}

sub _add_host_to_hostfile {
    my($host, $hostfile, $key, $hash) = @_;
    unless (-e $hostfile) {
        require File::Basename;
        my $dir = File::Basename::dirname($hostfile);
        unless (-d $dir) {
            require File::Path;
            File::Path::mkpath([ $dir ])
                or die "Can't create directory $dir: $!";
        }
    }
    my $data;
    open my $fh, '>>', $hostfile or croak "Can't write to $hostfile: $!";
    if ($hash) {
        use Crypt::PRNG qw( random_bytes );
        my $rawsalt = random_bytes(SALT_LEN);
        my $salt = encode_b64($rawsalt);
        my $hash = encode_b64(hmac('SHA1',$rawsalt,$host));
        $data = join(' ', "|1|$salt|$hash", $key->dump_public);
    }
    else {
        $data = join(' ', $host, $key->dump_public);
    }
    print $fh $data,"\n";
    close $fh or croak "Can't close $hostfile: $!";
}

1;
