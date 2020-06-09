## Let's encrypt DNS provisioning

This is a MirageOS unikernel which provisions TLS certificates using
[let's encrypt](https://letsencrypt.org/). It looks for certificate signing
requests, stored as TLSA records in DNS zones, and uses the let's encrypt
ACME DNS challenge to retrieve certificates. The certificate chain is stored
in DNS as TLSA record as well. This unikernel also ensures that certificates
are valid for at least two weeks.

This can be used with [dns-primary-git](https://github.com/roburio/dns-primary-git).

## Installation from source

To install this unikernel from source, you need to have
[opam](https://opam.ocaml.org) (>= 2.0.0) and
[ocaml](https://ocaml.org) (>= 4.07.0) installed. Also,
[mirage](https://mirageos.org) is required (>= 3.7.7). Please follow the
[installation instructions](https://mirageos.org/wiki/install).

The following steps will clone this git repository and compile the unikernel:

```bash
$ git clone https://github.com/roburio/dns-letsencrypt-secondary.git
$ mirage configure -t <your-favourite-target>
$ make depend
$ make
```

## Installing as binary

There are not yet any binaries available, but work is underway to provide
reproducible binaries.

## Questions?

Please open an issue if you have questions, feature requests, or comments.
