There are many scenarios of OCSP use. One of the simplest practical use cases
for clients is sending OCSP requests to the OCSP responder upon validation of
the server certificate during the TLS handshake. See the basic implementation
of this scenario in directory [*client-ocsp*](test/client-ocsp). To test this
scenario, run

```ShellSession
$ cd test/client-ocsp
$ cabal build
$ nginx -c /path/to/x509-ocsp/test/client-ocsp/nginx.conf
$ openssl ocsp -index /dev/null -port 8081 -rsigner ../data/certs/root/rootCA.crt -rkey ../data/certs/root/rootCA.key -CA ../data/certs/root/rootCA.crt -text
```

You may need to make the root certificate trusted by the system before running
Nginx. Below is how to make this in *Fedora*.

```ShellSession
$ sudo trust anchor --store ../data/certs/root/rootCA.crt
$ sudo update-ca-trust
```

The test itself should print *Response: In backend 8010*.

```ShellSession
$ cabal run
Response: In backend 8010
```

The output of the OpenSSL OCSP responder will contain details of the request
and the response.

