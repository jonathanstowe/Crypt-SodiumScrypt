# Crypt::SodiumScrypt

Scrypt password hashing using libsodium

![Build Status](https://github.com/jonathanstowe/Crypt-SodiumScrypt/workflows/CI/badge.svg)

## Synopsis


    use Crypt::SodiumScrypt;

    my $password =  'somepa55word';

    my $hash     =  scrypt-hash($password);

    if scrypt-verify($hash, $password ) {

        #  password ok

    }

## Description

This module provides a binding to the [scrypt](https://en.wikipedia.org/wiki/Scrypt) password hashing functions provided by [libsodium](https://libsodium.gitbook.io/doc/).

The Scrypt algorithm is designed to be prohibitively expensive in terms of time and memory for a brute force attack, so is considered relatively secure. However this means that it might not be suitable for use on resource constrained systems.

The hash returned by `scrypt-hash` is in the format used in `/etc/shadow` and can be verified by other libraries that understand the Scrypt algorithm ( such as the `libxcrypt` that is used for password hashing on some Linuc distributions.) By default the *interactive* limits for memory and CPU usage are used, which is a reasonable compromise for the time taken for both hashing and verification. If the `:sensitive` switch is supplied to `scrypt-hash` then both hashing and verification take significantly longer (and use more memory,) so this may not suitable for some applications.

The `scrypt-verify` should be able to verify passwords against Scrypt hashes produced by other libraries (that is the hash has the prefix *$7$*, ) but if you don't have control of the hashing parameters it may take longer than is desirable.


## Installation

You will need to have C<libsodium> installed for this to work, it is commonly packaged for various Linux distributions, so you should be able
to use the usual package management tools.

Assuming that you have a working installation of Rakudo then you should be able to install this with *zef* :

    zef install Crypt::SodiumScrypt

    # Or from a local clone

    zef install .

## Support

If you any suggestions/patches feel free to send them via:

https://github.com/jonathanstowe/Crypt-SodiumScrypt/issues

I've tested this with libsodium versions from 13 to 23, but if you find it doesn't work please let me know which version you have installed.

## Licence & Copyright

This is free software please see the [LICENCE](LICENCE) file in the distribution
for details.

© Jonathan Stowe 2019 - 2021
