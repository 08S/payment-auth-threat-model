# STRIDE threat model: payment flow

| STRIDE | Threat in payment flow | Example attack | Main control | Verification checklist |
|---|---|---|---|---|
| Spoofing | Attacker pretends to be user/client/API | Stolen session cookie, fake client_id, forged JWT | OAuth2 + PKCE, exact redirect URI, secure session cookie, JWT issuer/audience/alg validation | Session cookie is HttpOnly/Secure/SameSite; JWT rejects none/HS256; redirect URI exact match |
| Spoofing | Login/session fixation | Attacker forces victim to use known session id before login | Regenerate session id after login | Login calls req.session.regenerate() |
| Tampering | Payment amount/order modified in browser | Attacker changes amount from 1500 to 15 | Server-side price lookup, signed order intent, amount validation | API ignores client-calculated price and validates against order DB |
| Tampering | Authorization code injection/interception | Attacker injects stolen code into callback | PKCE S256 + state | Token endpoint verifies code_verifier hash equals stored code_challenge |
| Tampering | Duplicate charge | User refreshes/retries request or attacker replays POST | Idempotency-Key, one-time payment intent state machine | Same idempotency key returns same result, does not create new charge |
| Repudiation | User denies payment or admin action | No proof of who/when/what | Tamper-evident audit logs with user id, client id, request id, PSP reference | Logs include correlation id, subject, action, status, timestamp |
| Information disclosure | Tokens or card/payment data leaked | Access token in localStorage stolen by XSS; sensitive logs | HttpOnly cookies for sessions, short-lived access token, avoid logging secrets, PCI tokenization | Logs redact Authorization, refresh tokens, card data |
| Information disclosure | JWT accepted for wrong service | Token minted for another audience accepted by payment API | Strict aud, iss, exp, nbf, typ validation | Payment API rejects wrong audience/issuer/type |
| Denial of service | Auth/token endpoint abused | Brute force login or refresh attempts | Rate limiting, lockout, WAF, small JSON limit | Login/token endpoints rate-limited and alert on spikes |
| Denial of service | Payment API duplicate processing | Replay storm to create many charges | Idempotency and queue/backpressure | Payment creation is idempotent and bounded |
| Elevation of privilege | Customer accesses another user payment | Changing /payments/{id} | Object-level authorization / BOLA prevention | Query by payment_id AND owner_user_id |
| Elevation of privilege | JWT alg confusion | App trusts token header alg and treats RSA public key as HMAC secret | Pin algorithm RS256 and verification key type | Validator allowlists RS256 only and rejects HS256/none |
| Elevation of privilege | CSRF performs payment while user logged in | Malicious website submits POST using victim cookie | SameSite cookie + CSRF token in custom header + origin checks | State-changing endpoints require X-CSRF-Token |

## Risk priority

1. Broken authorization / BOLA on payment IDs.
2. Payment amount tampering.
3. JWT validation mistakes, especially algorithm confusion and missing audience checks.
4. Refresh-token theft/replay.
5. CSRF on state-changing cookie-authenticated endpoints.
6. Missing idempotency causing duplicate charges.
