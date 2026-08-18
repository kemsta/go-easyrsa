# Crypto test fixtures

`openssl-encrypted-pkcs8.pem` is a disposable 1024-bit RSA test key protected
with the known password `test-pass`. It contains no production material.

It was generated with OpenSSL 3.6.1:

```sh
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:1024 \
  -aes-256-cbc \
  -pass pass:test-pass \
  -out openssl-encrypted-pkcs8.pem
```

The fixture verifies that `UnmarshalPrivateKey` accepts OpenSSL's standard
PBES2-encrypted PKCS#8 output.
