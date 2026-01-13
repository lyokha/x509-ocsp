Generate test certificates and DER files from scratch
=====================================================

The certificates in directory *certs/* and files *req.der* and *resp.der* can
be created from scratch.

Generate root and server certificates
-------------------------------------

Create the root certificate and a signing request for the server certificate.

```ShellSession
$ openssl genrsa -out certs/root/rootCA.key 2048
$ openssl req -new -x509 -days 365 -key certs/root/rootCA.key -out certs/root/rootCA.crt -subj '/C=US/ST=California/L=San Francisco/O=My Company/OU=OCSP Test/CN=My Company Root/UID=testOCSP'
$ openssl req -new -newkey rsa:2048 -nodes -out certs/server/server.csr -subj '/C=US/ST=California/L=San Francisco/O=My Company/OU=OCSP Test/CN=localhost/UID=testOCSP' -keyout certs/server/server.key -config certs/openssl.cnf
```

Create and sign the server certificate.

```ShellSession
$ openssl x509 -req -days 365 -in certs/server/server.csr -CA certs/root/rootCA.crt -CAkey certs/root/rootCA.key -set_serial 01 -out certs/server/server.crt -extfile certs/openssl.cnf -extensions v3_exts
```

(Note, however, that for the sake of convenience, both root and server
certificates in this repository were actually built with option *-days 36500*.)

Make the root certificate trusted by the system (the following commands have
meaning in *Fedora*, other systems may require other commands).

```ShellSession
$ sudo trust anchor --store certs/root/rootCA.crt
$ sudo update-ca-trust
```

Generate files req.der and resp.der for cabal test
--------------------------------------------------

Create database *index.txt* and put there the server certificate.

```ShellSession
$ touch index.txt
$ openssl ca -valid certs/server/server.crt -keyfile certs/root/rootCA.key -cert certs/root/rootCA.crt -config certs/openssl.cnf
```

Run OpenSSL OCSP responder for getting a response.

```ShellSession
$ openssl ocsp -index index.txt -port 8081 -rsigner certs/root/rootCA.crt -rkey certs/root/rootCA.key -CA certs/root/rootCA.crt -text
```

Generate request and response files in DER format.

```ShellSession
$ openssl ocsp -issuer certs/root/rootCA.crt -cert certs/server/server.crt -reqout req.der -no_nonce
$ openssl ocsp -issuer certs/root/rootCA.crt -cert certs/server/server.crt -url http://localhost:8081 -respout resp.der
```

Generate certificate chain for using in the client-ocsp test
------------------------------------------------------------

```ShellSession
$ cat certs/server/server.crt certs/root/rootCA.crt > certs/server-chain.crt
```

