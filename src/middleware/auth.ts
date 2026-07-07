import type { NextFunction, Request, Response } from 'express';
import { verifyAccessToken } from '../security/jwt.js';

export type AuthenticatedRequest = Request & {
  auth?: {
    sub: string;
    scope: string;
    clientId: string;
    role: string;
  };
};

export async function requireAccessToken(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  try {
    const authHeader = req.header('authorization') ?? '';
    const [scheme, token] = authHeader.split(' ');

    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ error: 'missing_bearer_token' });
    }

    const payload = await verifyAccessToken(token);

    req.auth = {
      sub: String(payload.sub),
      scope: String(payload.scope ?? ''),
      clientId: String(payload.client_id ?? ''),
      role: String(payload.role ?? '')
    };

    return next();
  } catch {
    return res.status(401).json({ error: 'invalid_access_token' });
  }
}

export function requireScope(scope: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const scopes = new Set((req.auth?.scope ?? '').split(' ').filter(Boolean));
    if (!scopes.has(scope)) {
      return res.status(403).json({ error: 'insufficient_scope', required: scope });
    }
    return next();
  };
}
