import { config } from '../config.js';
import type { AuthorizationCodeRecord, OAuthClient, RefreshTokenRecord, UserRecord } from '../types.js';

// Demo store only. Replace with PostgreSQL/Redis in production.
export const clients = new Map<string, OAuthClient>([
  [
    config.demoClientId,
    {
      clientId: config.demoClientId,
      redirectUris: [config.demoRedirectUri],
      allowedScopes: ['openid', 'profile', 'payments:read', 'payments:create']
    }
  ]
]);

export const users = new Map<string, UserRecord>([
  [
    'user_123',
    {
      id: 'user_123',
      username: 'shubham@example.com',
      passwordHash:
        'prod-demo-salt-change-me-32-bytes!!:uAkbyoXj6X1p0mBMqtSJZBPXOYAl0jrd3et4p2i8MoWYwGQ-904KlkEZR7DAlJg4kBKTBjbGSx8fZoJfG2wnCg',
      role: 'customer'
    }
  ]
]);

export const authorizationCodes = new Map<string, AuthorizationCodeRecord>();
export const refreshTokensByHash = new Map<string, RefreshTokenRecord>();

export function findUserByUsername(username: string) {
  return [...users.values()].find((user) => user.username === username);
}

export function revokeRefreshTokenFamily(familyId: string) {
  for (const token of refreshTokensByHash.values()) {
    if (token.familyId === familyId && !token.revokedAt) {
      token.revokedAt = Date.now();
    }
  }
}
