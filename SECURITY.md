# Security Policy

## Supported Use

This repository is a hardened reference implementation for an OAuth2 + PKCE payment authorization flow. Treat it as a starting point for production architecture, not a complete payment platform by itself.

Before production use, replace all in-memory stores with durable infrastructure, store secrets in a secrets manager or KMS/HSM, add audit logging, enable monitoring, and complete an application security review.

## Reporting Vulnerabilities

Please do not open public issues for vulnerabilities. Report security findings privately to the repository owner.

Include:

- affected endpoint or component
- impact and exploitability
- reproduction steps
- recommended fix, if known

## Production Requirements

- Run only behind HTTPS.
- Use strong unique `SESSION_SECRET` values.
- Provide managed JWT signing keys with planned rotation.
- Use Redis/PostgreSQL or equivalent durable stores.
- Hash passwords with a production password hashing policy.
- Add centralized audit logs and alerting.
- Run dependency, SAST, and integration security checks in CI.

