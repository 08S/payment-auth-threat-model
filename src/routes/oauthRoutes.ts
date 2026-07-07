import type { Request, Response, Router } from 'express';
import express from 'express';
import { v4 as uuid } from 'uuid';
import { z } from 'zod';
import { config } from '../config.js';
import { randomBase64Url, sha256Base64Url, hashSecret, timingSafeEqualString } from '../security/random.js';
import { signAccessToken } from '../security/jwt.js';
import { authorizationCodes, clients, refreshTokensByHash, revokeRefreshTokenFamily, users } from '../store/memoryStore.js';
import { rateLimit } from '../middleware/rateLimit.js';

export const oauthRoutes: Router = express.Router();

const authorizeSchema = z.object({
  response_type: z.literal('code'),
  client_id: z.string(),
  redirect_uri: z.string().url(),
  scope: z.string().optional().default('openid profile payments:read'),
  state: z.string().min(8),
  code_challenge: z.string().min(43).max(128),
  code_challenge_method: z.literal('S256')
});

const tokenSchema = z.discriminatedUnion('grant_type', [
  z.object({
    grant_type: z.literal('authorization_code'),
    client_id: z.string(),
    code: z.string().min(20),
    redirect_uri: z.string().url(),
    code_verifier: z.string().min(43).max(128)
  }),
  z.object({
    grant_type: z.literal('refresh_token'),
    client_id: z.string(),
    refresh_token: z.string().min(32)
  })
]);

function validateClient(clientId: string, redirectUri?: string) {
  const client = clients.get(clientId);
  if (!client) return null;

  // Exact redirect URI matching prevents open redirect and code leakage.
  if (redirectUri && !client.redirectUris.includes(redirectUri)) return null;
  return client;
}

function normalizeScope(requestedScope: string, allowedScopes: string[]) {
  const requested = requestedScope.split(' ').filter(Boolean);
  const allowed = new Set(allowedScopes);
  if (requested.length === 0 || requested.some((scope) => !allowed.has(scope))) return null;
  return requested.join(' ');
}

oauthRoutes.get('/authorize', (req: Request, res: Response) => {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'login_required',
      message: 'Call GET /session/csrf-token, then POST /session/login before /oauth/authorize.'
    });
  }

  const parsed = authorizeSchema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_authorize_request' });

  const client = validateClient(parsed.data.client_id, parsed.data.redirect_uri);
  if (!client) return res.status(400).json({ error: 'invalid_client_or_redirect_uri' });

  const scope = normalizeScope(parsed.data.scope, client.allowedScopes);
  if (!scope) return res.status(400).json({ error: 'invalid_scope' });
  const rawCode = randomBase64Url(32);
  const codeHash = hashSecret(rawCode);

  authorizationCodes.set(codeHash, {
    codeHash,
    clientId: client.clientId,
    userId: req.session.userId,
    redirectUri: parsed.data.redirect_uri,
    codeChallenge: parsed.data.code_challenge,
    scope,
    expiresAt: Date.now() + 1000 * 60 * 5
  });

  const redirectUrl = new URL(parsed.data.redirect_uri);
  redirectUrl.searchParams.set('code', rawCode);
  redirectUrl.searchParams.set('state', parsed.data.state);

  return res.redirect(302, redirectUrl.toString());
});

oauthRoutes.post('/token', rateLimit({ name: 'token', windowMs: 60_000, max: 20 }), async (req: Request, res: Response) => {
  const parsed = tokenSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_token_request' });

  if (parsed.data.grant_type === 'authorization_code') {
    const client = validateClient(parsed.data.client_id, parsed.data.redirect_uri);
    if (!client) return res.status(400).json({ error: 'invalid_client_or_redirect_uri' });

    const codeHash = hashSecret(parsed.data.code);
    const record = authorizationCodes.get(codeHash);

    if (!record || record.usedAt || record.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'invalid_or_expired_code' });
    }

    if (record.clientId !== parsed.data.client_id || record.redirectUri !== parsed.data.redirect_uri) {
      return res.status(400).json({ error: 'code_binding_failed' });
    }

    const expectedChallenge = sha256Base64Url(parsed.data.code_verifier);
    if (!timingSafeEqualString(expectedChallenge, record.codeChallenge)) {
      return res.status(400).json({ error: 'pkce_verification_failed' });
    }

    record.usedAt = Date.now();

    const user = users.get(record.userId);
    if (!user) return res.status(500).json({ error: 'user_missing' });

    const accessToken = await signAccessToken({
      sub: user.id,
      client_id: client.clientId,
      scope: record.scope,
      role: user.role
    });

    const refreshToken = randomBase64Url(64);
    const refreshTokenHash = hashSecret(refreshToken);
    const familyId = uuid();

    refreshTokensByHash.set(refreshTokenHash, {
      tokenHash: refreshTokenHash,
      familyId,
      userId: user.id,
      clientId: client.clientId,
      scope: record.scope,
      issuedAt: Date.now(),
      expiresAt: Date.now() + config.refreshTokenTtlSeconds * 1000
    });

    return res.json({
      token_type: 'Bearer',
      access_token: accessToken,
      expires_in: config.accessTokenTtlSeconds,
      refresh_token: refreshToken,
      scope: record.scope
    });
  }

  const client = validateClient(parsed.data.client_id);
  if (!client) return res.status(400).json({ error: 'invalid_client' });

  const tokenHash = hashSecret(parsed.data.refresh_token);
  const oldRecord = refreshTokensByHash.get(tokenHash);

  if (!oldRecord) return res.status(400).json({ error: 'invalid_refresh_token' });

  if (oldRecord.revokedAt) {
    // Replay detection: old refresh token used again after rotation.
    // Assume theft and revoke the entire token family.
    revokeRefreshTokenFamily(oldRecord.familyId);
    return res.status(401).json({ error: 'refresh_token_reuse_detected' });
  }

  if (oldRecord.expiresAt < Date.now() || oldRecord.clientId !== parsed.data.client_id) {
    oldRecord.revokedAt = Date.now();
    return res.status(401).json({ error: 'invalid_refresh_token' });
  }

  oldRecord.revokedAt = Date.now();

  const newRefreshToken = randomBase64Url(64);
  const newRefreshTokenHash = hashSecret(newRefreshToken);
  oldRecord.replacedByHash = newRefreshTokenHash;

  refreshTokensByHash.set(newRefreshTokenHash, {
    tokenHash: newRefreshTokenHash,
    familyId: oldRecord.familyId,
    userId: oldRecord.userId,
    clientId: oldRecord.clientId,
    scope: oldRecord.scope,
    issuedAt: Date.now(),
    expiresAt: Date.now() + config.refreshTokenTtlSeconds * 1000
  });

  const user = users.get(oldRecord.userId);
  if (!user) return res.status(500).json({ error: 'user_missing' });

  const accessToken = await signAccessToken({
    sub: oldRecord.userId,
    client_id: oldRecord.clientId,
    scope: oldRecord.scope,
    role: user.role
  });

  return res.json({
    token_type: 'Bearer',
    access_token: accessToken,
    expires_in: config.accessTokenTtlSeconds,
    refresh_token: newRefreshToken,
    scope: oldRecord.scope
  });
});
