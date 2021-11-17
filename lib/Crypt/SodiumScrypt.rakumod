use v6;

use NativeCall :TEST,:DEFAULT;
use NativeLibs:ver<0.0.5+>;

use NativeHelpers::Array;

=begin pod

=head1  NAME

Crypt::SodiumScrypt - scrypt password hashing using libsodium


=head1 SYNOPSIS

=begin code

use Crypt::SodiumScrypt;

my $password =  'somepa55word';

my $hash     =  scrypt-hash($password);

if scrypt-verify($hash, $password ) {

    #  password ok

}

=end code

=head1 DESCRIPTION

This module provides a binding to the
L<scrypt|https://en.wikipedia.org/wiki/Scrypt> password hashing functions
provided by L<libsodium|https://libsodium.gitbook.io/doc/>.

The Scrypt algorithm is designed to be prohibitively expensive in terms
of time and memory for a brute force attack, so is considered relatively
secure. However this means that it might not be suitable for use on
resource constrained systems.

The hash returned by C<scrypt-hash> is in the format used in
C</etc/shadow> and can be verified by other libraries that understand the
Scrypt algorithm ( such as the C<libxcrypt> that is used for password
hashing on some Linuc distributions.)  By default the I<interactive>
limits for memory and CPU usage are used, which is a reasonable
compromise for the time taken for both hashing and verification.  If the
C<:sensitive> switch is supplied to C<scrypt-hash> then both hashing
and verification take significantly longer (and use more memory,) so
this may not suitable for some applications.

The C<scrypt-verify> should be able to verify passwords against Scrypt
hashes produced by other libraries (that is the hash has the prefix I<$7$>, )
but if you don't have control of the hashing parameters it may take longer
than is desirable.

=end pod

module Crypt::SodiumScrypt {


    constant LIB = NativeLibs::Searcher.at-runtime(
        'sodium',
        'crypto_pwhash_strbytes',
        15..23
    );


    sub crypto_pwhash_scryptsalsa208sha256_strbytes( --> size_t ) is native(LIB) { * }

    constant SCRYPT_STRBYTES = crypto_pwhash_scryptsalsa208sha256_strbytes();


    sub crypto_pwhash_scryptsalsa208sha256_opslimit_interactive( --> size_t ) is native(LIB) { * }

    constant OPSLIMIT_INTERACTIVE = crypto_pwhash_scryptsalsa208sha256_opslimit_interactive();

    sub crypto_pwhash_scryptsalsa208sha256_memlimit_interactive( --> size_t ) is native(LIB) { * }

    constant MEMLIMIT_INTERACTIVE = crypto_pwhash_scryptsalsa208sha256_memlimit_interactive();

    sub crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive( --> size_t ) is native(LIB) { * }

    constant OPSLIMIT_SENSITIVE = crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive();

    sub crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive( --> size_t ) is native(LIB) { * }

    constant MEMLIMIT_SENSITIVE = crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive();

    sub crypto_pwhash_scryptsalsa208sha256_str(CArray[uint8] $out, Str $passwd, ulonglong $passwdlen, ulonglong $opslimit, size_t $memlimit --> int32) is native(LIB) { * }

    sub scrypt-hash(Str $password, Bool :$sensitive --> Str ) is export {

        my $opslimit = $sensitive ?? OPSLIMIT_SENSITIVE !! OPSLIMIT_INTERACTIVE;
        my $memlimit = $sensitive ?? MEMLIMIT_SENSITIVE !! MEMLIMIT_INTERACTIVE;
        my $password-length = $password.encode.bytes;
        my $hashed        = CArray[uint8].allocate(SCRYPT_STRBYTES);

        if crypto_pwhash_scryptsalsa208sha256_str($hashed, $password, $password-length, $opslimit, $memlimit) {
            die 'out of memory in scrypt-hash';
        }

        my $buf = copy-carray-to-buf($hashed, SCRYPT_STRBYTES);
        $buf.decode.subst(/\0+$/,'');
    }

    sub crypto_pwhash_scryptsalsa208sha256_str_verify(Str $str, Str $passwd, ulonglong $passwdlen --> int32) is native(LIB) { * }

    sub scrypt-verify(Str $hash, Str $password --> Bool ) is export {
        my $password-length = $password.encode.bytes;
        !crypto_pwhash_scryptsalsa208sha256_str_verify($hash, $password, $password-length);
    }

}

# vim: ft=raku
