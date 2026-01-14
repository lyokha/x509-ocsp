Basic X509 OCSP implementation in Haskell
=========================================

[![Build Status](https://github.com/lyokha/x509-ocsp/workflows/CI/badge.svg)](https://github.com/lyokha/x509-ocsp/actions?query=workflow%3ACI)
[![Hackage](https://img.shields.io/hackage/v/x509-ocsp.svg?label=hackage%20%7C%20x509-ocsp&logo=haskell&logoColor=%239580D1)](https://hackage.haskell.org/package/x509-ocsp)

This module helps building OCSP requests and parse OCSP responses in Haskell.

There are many scenarios of OCSP use. One of the simplest practical use cases
for clients is sending OCSP requests to the OCSP responder upon validation of
the server certificate during the TLS handshake. See the basic implementation
of this scenario in directory [*client-ocsp*](test/client-ocsp). To test this
scenario, run

```ShellSession
$ cd test/client-ocsp
$ cabal build
$ nginx -c /path/to/x509-ocsp/test/client-ocsp/nginx.conf
```

You may need to make the root certificate trusted by the system before running
Nginx. Below is how to do this in *Fedora*.

```ShellSession
$ sudo trust anchor --store ../data/certs/root/rootCA.crt
$ sudo update-ca-trust
```

Now let's create a database file *index.txt* (its path must be equal to what
written in clause *database* in file *../data/certs/openssl.cnf*),

```ShellSession
$ touch ../data/index.txt
```

and put there the server certificate.

```ShellSession
$ openssl ca -valid ../data/certs/server/server.crt -keyfile ../data/certs/root/rootCA.key -cert ../data/certs/root/rootCA.crt -config ../data/certs/openssl.cnf
```

The certificate has *good* status because we used option *-valid*. Run OpenSSL
OCSP responder in a separate terminal window to see what it will print out.

```ShellSession
$ openssl ocsp -index ../data/index.txt -port 8081 -rsigner ../data/certs/root/rootCA.crt -rkey ../data/certs/root/rootCA.key -CA ../data/certs/root/rootCA.crt -text
```

Run the test. It should print *Response: In backend 8010*.

```ShellSession
$ cabal run
Response: In backend 8010
```

The output of the OCSP responder must contain details of the request and the
response.

Let's revoke the certificate.

```ShellSession
$ openssl ca -revoke ../data/certs/server/server.crt -keyfile ../data/certs/root/rootCA.key -cert ../data/certs/root/rootCA.crt -config ../data/certs/openssl.cnf
```

Restart the OCSP responder and look at what *cabal run* will print (you may also
run *cabal run* twice instead of restarting the responder).

```ShellSession
$ cabal run
Exception: HttpExceptionRequest Request {
  host                 = "localhost"
  port                 = 8010
  secure               = True
  requestHeaders       = []
  path                 = "/"
  queryString          = ""
  method               = "GET"
  proxy                = Nothing
  rawBody              = False
  redirectCount        = 10
  responseTimeout      = ResponseTimeoutDefault
  requestVersion       = HTTP/1.1
  proxySecureMode      = ProxySecureWithConnect
}
 (InternalException (HandshakeFailed (Error_Protocol "certificate rejected: [CacheSaysNo \"OCSP: bad certificate status OCSPRespCertRevoked\"]" CertificateUnknown)))
```

 The certificate has been revoked and the handshake fails.

