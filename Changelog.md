### 0.4.0.0

- Field *ocspRespCerts* of *OCSPResponseVerificationData* now contains a list
  of *signed certificates* augmented by *DER*-encoded *tbsCertificate* as defined
  in *rfc5280*. This enables check of the OCSP Signature Authority Delegation.
  See a basic implementation of the check in the *client-ocsp* example.

### 0.3.1.0

- Add function *getOCSPResponseVerificationData'* which is similar to
  *getOCSPResponseVerificationData* except it accepts the OCSP response payload
  in *ASN.1* format. See how it can be used in the *client-ocsp* example.

### 0.3.0.0

- Add function *getOCSPResponseVerificationData* to help verify the signature of
  the OCSP response. See how it can be used in the *client-ocsp* example.

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

