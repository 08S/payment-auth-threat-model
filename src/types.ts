import 'express-session';

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    csrfToken?: string;
  }
}

export type OAuthClient = {
  clientId: string;
  redirectUris: string[];
  allowedScopes: string[];
};

export type UserRecord = {
  id: string;
  username: string;
  passwordHash: string;
  role: string;
};

export type AuthorizationCodeRecord = {
  codeHash: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  expiresAt: number;
  usedAt?: number;
};

export type RefreshTokenRecord = {
  tokenHash: string;
  familyId: string;
  userId: string;
  clientId: string;
  scope: string;
  expiresAt: number;
  issuedAt: number;
  revokedAt?: number;
  replacedByHash?: string;
};
