# Authentication Web Server

- Spring Boot Security project

## Generate Keypair

```bash
# create rsa key pair

openssl genrsa -out keypair.pem 2048
```

```bash
# extract public key

openssl rsa -in keypair.pem -pubout -out public.pem
```

```bash
# create private key in PKCS#8 format

openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem
```
