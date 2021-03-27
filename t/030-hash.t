#!/usr/bin/env raku

use v6;

use Test;
use LibraryCheck;

sub check-lib-version() {
    my Str $name = 'sodium';
    my Int $lower = 13;
    my Int $upper = 23;

    my $rc = False;

    for $lower .. $upper -> $version-number {
        my $version = Version.new($version-number);

        if library-exists($name, $version) {
            $rc = True;
            last;
        }
    }

    $rc;
}

if check-lib-version() {
    require Crypt::SodiumScrypt <&scrypt-hash &scrypt-verify>;

    my @chars = (|("a" .. "z"), |("A" .. "Z"), |(0 .. 9));

    subtest  {
        my $password = @chars.pick(20).join;
        my $hash;
        lives-ok { $hash = scrypt-hash($password) }, 'scrypt-hash';
        like $hash, /^'$7$'/, 'the correct hash prefix';
        lives-ok { ok scrypt-verify($hash, $password), "verify ok" }, 'scrypt-verify';
        lives-ok { nok scrypt-verify($hash, $password.comb.reverse.join), "verify nok with wrong password" }, 'scrypt-verify';
    }, 'with interactive profile';
    subtest  {
        my $password = @chars.pick(20).join;
        my $hash;
        lives-ok { $hash = scrypt-hash($password, :sensitive) }, 'scrypt-hash';
        like $hash, /^'$7$'/, 'the correct hash prefix';
        lives-ok { ok scrypt-verify($hash, $password), "verify ok" }, 'scrypt-verify';
        lives-ok { nok scrypt-verify($hash, $password.comb.reverse.join), "verify nok with wrong password" }, 'scrypt-verify';
    }, 'with sensitive profile';
}
else {
    diag "libsodium is not installed, skipping tests";
    skip "No libsodium, skipping tests";
}



done-testing;
# vim: expandtab shiftwidth=4 ft=raku
