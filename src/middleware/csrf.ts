import type { NextFunction, Request, Response } from 'express';
import { config, isProduction } from '../config.js';
import { randomBase64Url, timingSafeEqualString } from '../security/random.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function issueCsrfToken(req: Request, res: Response) {
  const token = randomBase64Url(32);
  req.session.csrfToken = token;

  // Non-HttpOnly so SPA can copy it into the X-CSRF-Token header.
  // Do not use this cookie as the source of truth; the server session is.
  res.cookie('csrf_token', token, {
    httpOnly: false,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    sameSite: 'lax',
    path: '/'
  });

  return token;
}

export function csrfProtection(req: Request, res: Response, next: NextFunction) {
  if (SAFE_METHODS.has(req.method)) return next();

  const origin = req.header('origin');
  if (origin && !config.trustedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'untrusted_origin' });
  }

  if (isProduction && !origin) {
    return res.status(403).json({ error: 'missing_origin' });
  }

  const sessionToken = req.session.csrfToken;
  const headerToken = req.header('x-csrf-token');

  if (!sessionToken || !headerToken || !timingSafeEqualString(sessionToken, headerToken)) {
    return res.status(403).json({ error: 'csrf_failed', message: 'Missing or invalid CSRF token' });
  }

  return next();
}
