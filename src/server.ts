import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { config } from './config.js';
import { sessionMiddleware } from './middleware/session.js';
import { csrfProtection } from './middleware/csrf.js';
import { oauthRoutes } from './routes/oauthRoutes.js';
import { paymentRoutes } from './routes/paymentRoutes.js';
import { sessionRoutes } from './routes/sessionRoutes.js';
import { getJwks } from './security/jwt.js';

const app = express();

app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(sessionMiddleware);

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/.well-known/jwks.json', async (_req, res) => res.json(await getJwks()));

app.use('/session', sessionRoutes);

// CSRF is needed for cookie/session endpoints and token refresh if refresh token is kept in a cookie.
// This demo accepts refresh_token in JSON, but keeps CSRF protection on token POST to demonstrate defense.
app.use('/oauth', csrfProtection, oauthRoutes);
app.use('/api', paymentRoutes);

app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

app.listen(config.port, () => {
  console.log(`Auth service running at http://localhost:${config.port}`);
});
