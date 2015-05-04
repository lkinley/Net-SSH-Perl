# $Id: Hosts.pm,v 1.10 2008/10/21 15:41:02 turnstep Exp $

package Net::SSH::Perl::Util::Hosts;
use strict;

use Net::SSH::Perl::Constants qw( :hosts );

use Carp qw( croak );

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

			## Make sure we have the required helper modules.
			## If not, give one warning per file
			next if $hashmodules >= 1;
			if (!$hashmodules) {
				eval { require Digest::HMAC_SHA1; };
				if ($@) {
					$hashmodules += 1;
				}
				eval { require MIME::Base64; };
				if ($@) {
					$hashmodules += 2;
				}
				if ($hashmodules) {
					my $msg = sprintf qq{Cannot parse hashed known_hosts file "$hostfile" without %s%s\n},
						$hashmodules == 2 ? 'MIME::Base64' : 'Digest::HMAC_SHA1',
							$hashmodules == 3 ? ' and MIME::Base64' : '';
					warn $msg;
					next;
				}
				else {
					$hashmodules = -1;
				}
			}

			my $rawsalt = MIME::Base64::decode_base64($salt);
			my $hash = MIME::Base64::encode_base64(Digest::HMAC_SHA1::hmac_sha1($host,$rawsalt));
			chomp $hash;
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
    my($host, $hostfile, $key) = @_;
    unless (-e $hostfile) {
        require File::Basename;
        my $dir = File::Basename::dirname($hostfile);
        unless (-d $dir) {
            require File::Path;
            File::Path::mkpath([ $dir ])
                or die "Can't create directory $dir: $!";
        }
    }
    open my $fh, '>>', $hostfile or croak "Can't write to $hostfile: $!";
    print $fh join(' ', $host, $key->dump_public), "\n";
    close $fh or croak "Can't close $hostfile: $!";
}

1;
