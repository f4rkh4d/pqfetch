# pqfetch

TLS post-quantum readiness scanner. tells you, in one line per host, whether the server negotiates a hybrid post-quantum key exchange (`X25519MLKEM768`) or a classical one.

[![crates.io](https://img.shields.io/crates/v/pqfetch.svg)](https://crates.io/crates/pqfetch)
[![docs.rs](https://img.shields.io/docsrs/pqfetch)](https://docs.rs/pqfetch)
[![downloads](https://img.shields.io/crates/d/pqfetch.svg)](https://crates.io/crates/pqfetch)
[![ci](https://github.com/f4rkh4d/pqfetch/actions/workflows/ci.yml/badge.svg)](https://github.com/f4rkh4d/pqfetch/actions)
[![msrv](https://img.shields.io/badge/msrv-1.74-blue.svg)](#)
[![license](https://img.shields.io/crates/l/pqfetch.svg)](#license)

## why

the IETF TLS WG ships `X25519MLKEM768` (codepoint `0x11ec`) as the canonical hybrid post-quantum key exchange. browsers (Chrome, Firefox), edge networks (Cloudflare), and modern Rust TLS stacks (`rustls >= 0.23.27`) have it on. most other servers are still classical X25519 only. before 2030 a lot of TLS traffic that exists today will retroactively become readable to a sufficiently large quantum computer, so you might want to know which side of the line your favorite servers are on.

`pqfetch` is the simplest possible answer: connect with a client that prefers post-quantum hybrid and report the actual negotiated kex. one binary, no Wireshark, no python.

## install

```sh
cargo install pqfetch
```

## use

scan a few hosts:

```
$ pqfetch cloudflare.com github.com openai.com
host             tls   kx               pq?
cloudflare.com   1.3   X25519MLKEM768   yes
github.com       1.3   X25519            no
openai.com       1.3   X25519MLKEM768   yes
```

scan a built-in curated list of well-known sites:

```
$ pqfetch --curated
host                tls   kx               pq?
cloudflare.com      1.3   X25519MLKEM768   yes
google.com          1.3   X25519MLKEM768   yes
youtube.com         1.3   X25519MLKEM768   yes
github.com          1.3   X25519            no
amazon.com          1.3   X25519            no
apple.com           1.3   X25519MLKEM768   yes
microsoft.com       1.3   secp256r1         no
openai.com          1.3   X25519MLKEM768   yes
anthropic.com       1.3   X25519MLKEM768   yes
meta.com            1.3   X25519MLKEM768   yes
facebook.com        1.3   X25519MLKEM768   yes
x.com               1.3   X25519MLKEM768   yes
wikipedia.org       1.3   X25519MLKEM768   yes
stackoverflow.com   1.3   X25519MLKEM768   yes
rust-lang.org       1.3   X25519MLKEM768   yes
crates.io           1.3   X25519MLKEM768   yes
docs.rs             1.3   X25519MLKEM768   yes
```

machine-readable output:

```
$ pqfetch --json cloudflare.com github.com
{"host":"cloudflare.com","port":443,"tls":"1.3","kex":"X25519MLKEM768","pq":true}
{"host":"github.com","port":443,"tls":"1.3","kex":"X25519","pq":false}
```

custom port:

```
$ pqfetch example.com:8443
```

## what it tells you

three columns:

- **tls** the TLS protocol version actually negotiated (1.2 / 1.3).
- **kx**  the named group used for the key exchange. `X25519MLKEM768` is the IETF-WG-blessed hybrid; everything else is classical.
- **pq?** `yes` iff `kx` matches a hybrid post-quantum group. as of mid-2026 that's `X25519MLKEM768` and the older `X25519Kyber768Draft00`.

if `pq?` is `no`, the host has not yet enabled hybrid kex, even though `pqfetch`'s client offered it. that's a server-side configuration choice, not a fundamental capability gap.

## what it does not tell you

- not whether the server's certificate chain uses post-quantum signatures (that is a separate transition; ML-DSA / SLH-DSA aren't deployed in CA hierarchies yet).
- not whether the application-layer protocol on top of TLS is post-quantum (it never is, by definition; the kex is what protects the session against a future "harvest now, decrypt later" attack).
- not whether the server supports TLS 1.3 over QUIC (this binary uses plain TLS over TCP).

## how it works

uses [rustls 0.23](https://crates.io/crates/rustls) with the `prefer-post-quantum` feature flag and the `aws-lc-rs` crypto provider, which exposes `X25519MLKEM768` in its set of supported kx groups. for each host: TCP-connect, drive a TLS handshake, ask `ClientConnection::negotiated_key_exchange_group()` what was actually used, print, close.

no parallelism on purpose, the curated list is small and serial output reads more naturally.

## license

dual-licensed under MIT or Apache-2.0, at your option.
