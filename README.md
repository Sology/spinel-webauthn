# webauthn (spinel-webauthn)

The [webauthn](https://github.com/cedarcode/webauthn-ruby) gem, version 3.4.3, ported to Ruby that
[Spinel](https://github.com/matz/spinel) compiles: the relying-party half of the webauthn gem: registration and authentication options, attestation and assertion verification.

The class and method names are the gem's, and so are the answers: a program written against
CRuby and the gem compiles here unchanged. Where the port simplifies, the code says so. The
tests (`test/*.rb` with `.expected` output) compare with the real gem under CRuby.

```toml
# spin.toml
[dependencies]
webauthn = { git = "https://github.com/sology/spinel-webauthn" }
```

Needs Spinel's openssl package with RSA signature verification.

```console
$ spin test
```

The version follows the gem it reproduces (3.4.3); a newer gem release is ported here
before a program that locks it is built with this package.

## License

MIT, as the gem: see LICENSE (the gem's notice, which covers the code this is derived from).
