# Data-flow diagram: payment flow with secure auth

## Context

This DFD models a browser-based payment web app that uses OAuth2 Authorization Code + PKCE, an authorization server, a payment API, a payment service/provider, and a database.

```mermaid
flowchart LR
  U[Customer / Browser]
  FE[Payment Web App / SPA]
  AS[Auth Service\nOAuth2 + PKCE + Sessions]
  API[Payment API / Resource Server]
  DB[(Payment DB)]
  PSP[Payment Gateway / Bank / PSP]
  FRAUD[Fraud / Risk Engine]
  LOG[(Audit Logs / SIEM)]

  U -->|1. Login, CSRF token, payment request| FE
  FE -->|2. /authorize with code_challenge + state| AS
  AS -->|3. Auth session cookie HttpOnly SameSite| U
  AS -->|4. Authorization code redirect| FE
  FE -->|5. /token: code + code_verifier| AS
  AS -->|6. Access JWT + rotated refresh token| FE
  FE -->|7. Bearer JWT + Idempotency-Key| API
  API -->|8. Validate JWT issuer/audience/alg/scope| AS
  API -->|9. Create/read payment| DB
  API -->|10. Risk check| FRAUD
  API -->|11. Payment authorization/capture| PSP
  API -->|12. Security/payment events| LOG
  AS -->|13. Auth/token/session events| LOG
```

## Trust boundaries

1. Browser boundary: untrusted user device, JS runtime, extensions, cached data.
2. Internet boundary: TLS required between browser, frontend, auth service, and APIs.
3. Auth boundary: token issuance, session creation, PKCE validation, JWT signing.
4. Payment API boundary: JWT validation, scope check, object-level authorization, idempotency.
5. Third-party PSP boundary: external gateway/bank APIs and webhook callbacks.
6. Data boundary: payment DB and logs containing sensitive security/payment metadata.

## High-value assets

- Authorization code
- PKCE code verifier
- Session cookie
- Access token JWT
- Refresh token
- Payment amount, currency, status, beneficiary/merchant data
- Idempotency key
- PSP transaction reference
- Audit logs
