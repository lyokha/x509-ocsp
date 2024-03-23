### 0.2.0.0

- **Breaking changes**: flip the order of arguments in *encodeOCSPRequestASN1*
  and *encodeOCSPRequest* (the new order is *cert &#8594; issuerCert*).
- Various improvements in the *client-ocsp* example.

### 0.1.1.0

- Improvements in module *Data.X509.AIA*.
  + Throw an error when trying to encode *CA Issuers* data as this is not
    implemented.
  + Allow decoding of all variants of *string-like* *accessLocation* data.
  + List limitations of the module in the documentation.

### 0.1.0.0

- Initial version.

