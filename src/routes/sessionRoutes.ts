import type { Request, Response, Router } from 'express';
import express from 'express';
import { z } from 'zod';
import { findUserByUsername } from '../store/memoryStore.js';
import { csrfProtection, issueCsrfToken } from '../middleware/csrf.js';
import { rateLimit } from '../middleware/rateLimit.js';
import { verifyPassword } from '../security/password.js';

export const sessionRoutes: Router = express.Router();

const loginSchema = z.object({
  username: z.string().email(),
  password: z.string().min(8)
});

sessionRoutes.get('/csrf-token', (req: Request, res: Response) => {
  const token = issueCsrfToken(req, res);
  return res.json({ csrfToken: token });
});

sessionRoutes.post('/login', rateLimit({ name: 'login', windowMs: 60_000, max: 5 }), csrfProtection, async (req: Request, res: Response) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_login_payload' });

  const user = findUserByUsername(parsed.data.username);

  if (!user || !(await verifyPassword(parsed.data.password, user.passwordHash))) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  // Session fixation defense: never reuse a pre-login session id after authentication.
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'session_regeneration_failed' });

    req.session.userId = user.id;
    const csrfToken = issueCsrfToken(req, res);

    return res.json({ ok: true, userId: user.id, csrfToken });
  });
});

sessionRoutes.post('/logout', csrfProtection, (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'logout_failed' });

    res.clearCookie('pay.sid', { path: '/' });
    res.clearCookie('__Host-pay.sid', { path: '/' });
    res.clearCookie('csrf_token', { path: '/' });
    return res.status(204).send();
  });
});
