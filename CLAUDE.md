# CLAUDE.md

Guidance for Claude Code (and other agents) working in this repository.

## What this repo is

A **reference implementation + threat model** for a payment authentication flow. It pairs a working TypeScript/Express OAuth2+PKCE auth service with STRIDE threat-model documentation, so the code is meant to demonstrate the mitigations described in the docs. It is explicitly *not* production-ready (in-memory stores, demo credentials) — see "What to improve for production" in [README.md](README.md).

## Layout

```
docs/
  DFD.md      — Mermaid data-flow diagram + trust boundaries + high-value assets
  STRIDE.md   — STRIDE threat table (threat / attack / control / verification) + risk priority list
  API.md      — HTTP endpoint reference
  payment-auth.postman_collection.json — Postman collection for the numbered demo flow
src/
  server.ts               — Express app wiring: helmet, sessions, CSRF, routes
  config.ts                — env parsing + production safety gates (HTTPS, secret length, key presence)
  types.ts                 — shared types + express-session augmentation
  middleware/
    auth.ts                — Bearer JWT verification + scope guard (requireAccessToken, requireScope)
    csrf.ts                 — synchronizer-token CSRF (session token + X-CSRF-Token header) + origin check
    rateLimit.ts             — in-memory sliding-window rate limiter
    session.ts               — express-session config (HttpOnly, SameSite=lax, __Host- prefix in prod)
  routes/
    oauthRoutes.ts          — /oauth/authorize (PKCE S256), /oauth/token (auth-code exchange + refresh rotation/reuse detection)
    sessionRoutes.ts         — /session/csrf-token, /session/login (scrypt + regenerate), /session/logout
    paymentRoutes.ts         — /api/payments (BOLA-safe ownership check, idempotency-key handling)
  security/
    jwt.ts                   — RS256-only signing/verification, pinned alg/iss/aud/typ/kid, JWKS endpoint
    password.ts               — scrypt password verification (timing-safe compare)
    random.ts                  — CSPRNG helpers, sha256 hashing, timing-safe string compare
  store/memoryStore.ts       — in-memory demo store for clients/users/auth codes/refresh tokens (NOT production storage)
.github/workflows/security.yml — merge-gating CI: CodeQL, Semgrep, Gitleaks, npm audit, dependency-review, Trivy (fs + image), ZAP baseline DAST, Docker build
.gitleaks.toml / .semgrepignore / .trivyignore / .zap/rules.tsv — security-scanner tuning/suppressions
```

## Architecture in one paragraph

Browser → SPA does OAuth2 Authorization Code + PKCE (`S256` only) against this auth service, which also issues HttpOnly/SameSite session cookies (regenerated on login to defeat fixation) and CSRF tokens (synchronizer pattern, checked via `X-CSRF-Token` header + origin allowlist). Successful token exchange returns a short-lived RS256 JWT access token (`at+jwt`, pinned `iss`/`aud`/`kid`, alg allowlisted to defeat alg-confusion) plus a rotating refresh token; reusing a already-rotated refresh token revokes its whole token family (theft/replay defense). The payment API (`/api/payments`) requires Bearer JWT + scope, enforces object-level ownership (`ownerUserId === auth.sub`) to prevent BOLA, and uses an `Idempotency-Key` header keyed by user to avoid duplicate charges.

## Threat model ↔ code map

When touching auth/payment code, check it against [docs/STRIDE.md](docs/STRIDE.md) — each row names the control and the verification checklist item. Key invariants to preserve:

- PKCE is `S256`-only ([oauthRoutes.ts](src/routes/oauthRoutes.ts) `authorizeSchema`/`tokenSchema` use `z.literal('S256')`).
- Redirect URIs must match a client's registered URI **exactly** (`validateClient`).
- JWT verification must never trust the token's own `alg` header — `security/jwt.ts` pins `algorithms: ['RS256']` and an allowlisted `kid`.
- Session id must be regenerated after login (`sessionRoutes.ts` → `req.session.regenerate`).
- State-changing requests need a valid `X-CSRF-Token` matching the session-stored token, and origin must be in `config.trustedOrigins`.
- Payment reads/writes must check `ownerUserId` against the JWT `sub` — never trust a client-supplied user id.
- Refresh-token reuse (`revokedAt` already set) must revoke the entire token family, not just the reused token.
- `config.ts` throws on unsafe production config (non-HTTPS issuer/redirect, short/default session secret, missing PEM keys) — don't relax these checks without updating STRIDE.md.

## Running / developing

```bash
cp .env.example .env
npm install
npm run dev        # tsx watch src/server.ts, http://localhost:3000
npm run typecheck   # tsc --noEmit
npm run build        # tsc -> dist/
```

Demo login: `shubham@example.com` / `Password@123`. Full curl walk-through (CSRF → login → authorize → token → payment → refresh rotation) is in [README.md](README.md).

There are currently **no automated tests** (no test runner in `package.json`) — CI relies on typecheck/build + SAST/DAST/SCA scanning instead (see below). If you add tests, wire them into `.github/workflows/security.yml`'s `quality` job.

## CI / security gates (`.github/workflows/security.yml`)

Runs on every PR/push to `main`, gating merges:
- **Quality**: `npm run typecheck` + `npm run build`
- **SAST**: CodeQL (javascript-typescript, security-and-quality) + Semgrep (owasp-top-ten, js/ts/nodejs configs)
- **Secrets**: Gitleaks (`.gitleaks.toml`) with full git history
- **SCA**: `npm audit --audit-level=high`, GitHub dependency-review action, Trivy filesystem scan (`trivy.yaml`)
- **Container**: `docker build` + Trivy image scan
- **DAST**: boots the service (dev config, throwaway session secret) and runs OWASP ZAP baseline against it (`.zap/rules.tsv` for rule tuning)

Branch protection on `main` is expected to require these checks (see README "Security CI" section).

## Conventions to follow when editing

- ESM throughout (`"type": "module"`, `.js` extensions in relative imports even though source is `.ts`).
- Zod schemas validate all external input at route boundaries (OAuth params, login body, payment body).
- Secrets/tokens are hashed (`hashSecret`, sha256) before being stored as map keys — never store raw codes/refresh tokens.
- Use `timingSafeEqualString` for any secret/token comparison, not `===`.
- Keep the in-memory store demo-only; if you add persistence, replace `store/memoryStore.ts` rather than bolting persistence onto routes.
- If you change JWT claims, redirect handling, CSRF, or session behavior, update the corresponding row in [docs/STRIDE.md](docs/STRIDE.md) and, if the data flow changes, [docs/DFD.md](docs/DFD.md).
