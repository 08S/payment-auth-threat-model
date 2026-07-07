# API Reference

Base URL for local development:

```text
http://localhost:3000
```

## Health and Keys

```http
GET /health
GET /.well-known/jwks.json
```

## Session

```http
GET /session/csrf-token
POST /session/login
POST /session/logout
```

State-changing session requests require:

```http
X-CSRF-Token: <csrfToken>
```

## OAuth

```http
GET /oauth/authorize
POST /oauth/token
```

The authorization flow uses OAuth2 Authorization Code with PKCE `S256`.

## Payments

```http
GET /api/payments/:paymentId
POST /api/payments
```

Payment API requests require:

```http
Authorization: Bearer <accessToken>
```

Payment creation also requires:

```http
Idempotency-Key: <unique-key>
```

## Postman

Import [payment-auth.postman_collection.json](./payment-auth.postman_collection.json) into Postman and run the numbered requests in order.

