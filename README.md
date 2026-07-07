# Payment Auth Threat Model + Reference Auth Service

This package contains:

- `docs/DFD.md` — payment-flow data-flow diagram in Mermaid.
- `docs/STRIDE.md` — STRIDE threat model for the payment flow.
- `src/` — TypeScript/Express reference auth service.

The code demonstrates:

- OAuth2 Authorization Code + PKCE using `S256` only.
- Secure server-side sessions with session-id regeneration after login.
- CSRF protection using server-side synchronizer token + `X-CSRF-Token` header.
- Origin validation for browser state-changing requests.
- Login/token rate limiting.
- Scrypt password verification instead of plain-text password checks.
- JWT signing and validation with RS256 only, expected `iss`, `aud`, `typ`, and `kid`.
- Refresh-token rotation with token-family replay detection.
- Object-level payment ownership checks and idempotent payment creation.
- Payment API resource endpoints using Bearer JWT and scope checks.

> This is still a compact reference service. For real payment production use, replace the in-memory stores with Redis/PostgreSQL, store signing keys and secrets in KMS/HSM or a secrets manager, add audit logs, add monitoring, and run a professional security review.

## Run locally

```bash
cp .env.example .env
npm install
npm run dev
```

Server starts on:

```text
http://localhost:3000
```

Demo user:

```text
username: shubham@example.com
password: Password@123
```

## Production security gates

When `NODE_ENV=production`, the service now refuses unsafe defaults:

- `ISSUER` and `DEMO_REDIRECT_URI` must use HTTPS.
- `SESSION_SECRET` must be a unique high-entropy value of at least 64 characters.
- `JWT_PRIVATE_KEY_PEM` and `JWT_PUBLIC_KEY_PEM` must be provided.

For local development, the service can generate temporary JWT keys automatically. Do not rely on those generated keys in production because tokens will be invalidated on restart and key custody/rotation is not controlled.

## Demo flow with curl

### 1. Get CSRF token and session cookie

```bash
curl -i -c cookies.txt http://localhost:3000/session/csrf-token
```

Copy the `csrfToken` from the JSON response.

### 2. Login

```bash
curl -i -b cookies.txt -c cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <CSRF_TOKEN>" \
  -d '{"username":"shubham@example.com","password":"Password@123"}' \
  http://localhost:3000/session/login
```

The service regenerates the session id after login to defeat session fixation.

### 3. Start OAuth authorize request

Create a PKCE verifier/challenge in your frontend. Example Node one-liner:

```bash
node -e "const c=require('crypto'); const v=c.randomBytes(32).toString('base64url'); const ch=c.createHash('sha256').update(v).digest('base64url'); console.log({verifier:v, challenge:ch})"
```

Then open/call:

```bash
curl -i -b cookies.txt \
  "http://localhost:3000/oauth/authorize?response_type=code&client_id=payment-web&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback&scope=openid%20profile%20payments%3Aread%20payments%3Acreate&state=random-state-123&code_challenge=<CODE_CHALLENGE>&code_challenge_method=S256"
```

Copy the `code` from the `Location` redirect header.

### 4. Exchange code for tokens

```bash
curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <CSRF_TOKEN>" \
  -d '{
    "grant_type":"authorization_code",
    "client_id":"payment-web",
    "redirect_uri":"http://localhost:5173/callback",
    "code":"<AUTHORIZATION_CODE>",
    "code_verifier":"<CODE_VERIFIER>"
  }' \
  http://localhost:3000/oauth/token
```

### 5. Call payment API

```bash
curl -s \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  http://localhost:3000/api/payments/pay_demo_123
```

### 6. Create payment with idempotency key

```bash
curl -s \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: order_123_attempt_1" \
  -d '{"orderId":"order_123"}' \
  http://localhost:3000/api/payments
```

### 7. Refresh token rotation

```bash
curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <CSRF_TOKEN>" \
  -d '{
    "grant_type":"refresh_token",
    "client_id":"payment-web",
    "refresh_token":"<REFRESH_TOKEN>"
  }' \
  http://localhost:3000/oauth/token
```

Using the old refresh token again triggers `refresh_token_reuse_detected` and revokes the full token family.

## What to improve for production

- Use HTTPS everywhere.
- Use Redis/PostgreSQL for sessions, auth codes, and refresh tokens.
- Hash passwords with Argon2id or bcrypt.
- Add login/token rate limiting and account lockout.
- Add origin/referrer validation for browser state-changing requests.
- Store refresh tokens in HttpOnly Secure SameSite cookies or a hardened BFF architecture.
- Add device binding/risk checks for refresh tokens where appropriate.
- Use KMS/HSM for signing keys and support planned key rotation.
- Add audit logs with correlation IDs and redaction.
- Add integration tests for alg-confusion, CSRF failure, session fixation, and refresh-token replay.
