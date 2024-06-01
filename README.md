# Account Security

- Spring Security with OAuth2 Resource Server

## Summary

**MFA Setup**:

- User is logged in with username and password.
- User scans a QR code with Google Authenticator to set up MFA.
- User verifies the setup by providing a TOTP, which the server validates.
- Server returns recovery codes that can be used for authentication if, for example, user loses his
  device.

1. **Initial Authentication**:
    - User logs in with username and password.
    - If MFA is required, a pre-auth token is issued.

2. **MFA Verification**:
    - User provides the pre-auth token and TOTP.
    - Server verifies both the pre-auth token and TOTP.
    - Upon successful verification, the server issues a regular JWT for accessing protected
      resources and refresh token in a form of a cookie.

### Generate Keypair

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
