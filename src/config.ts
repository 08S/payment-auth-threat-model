import 'dotenv/config';

function requiredInProduction(name: string): string | undefined {
  const value = process.env[name];
  if (process.env.NODE_ENV === 'production' && !value) {
    throw new Error(`${name} must be set in production`);
  }
  return value;
}

function normalizePem(value: string | undefined): string | undefined {
  return value?.replace(/\\n/g, '\n');
}

const env = process.env.NODE_ENV ?? 'development';
const issuer = process.env.ISSUER ?? 'http://localhost:3000';
const demoRedirectUri = process.env.DEMO_REDIRECT_URI ?? 'http://localhost:5173/callback';
const sessionSecret = process.env.SESSION_SECRET ?? 'dev-only-change-me-dev-only-change-me-dev-only-change-me';
const jwtPrivateKeyPem = normalizePem(requiredInProduction('JWT_PRIVATE_KEY_PEM'));
const jwtPublicKeyPem = normalizePem(requiredInProduction('JWT_PUBLIC_KEY_PEM'));
const trustedOrigins = [...new Set([new URL(issuer).origin, new URL(demoRedirectUri).origin])];

if (env === 'production') {
  if (new URL(issuer).protocol !== 'https:' || new URL(demoRedirectUri).protocol !== 'https:') {
    throw new Error('ISSUER and DEMO_REDIRECT_URI must use HTTPS in production');
  }

  if (!process.env.SESSION_SECRET || sessionSecret.length < 64 || sessionSecret.includes('replace-with')) {
    throw new Error('SESSION_SECRET must be a unique high-entropy value of at least 64 characters in production');
  }
}

export const config = {
  env,
  port: Number(process.env.PORT ?? 3000),
  issuer,
  audience: process.env.AUDIENCE ?? 'payment-api',
  sessionSecret,
  demoClientId: process.env.DEMO_CLIENT_ID ?? 'payment-web',
  demoRedirectUri,
  trustedOrigins,
  jwtPrivateKeyPem,
  jwtPublicKeyPem,
  accessTokenTtlSeconds: Number(process.env.ACCESS_TOKEN_TTL_SECONDS ?? 900),
  refreshTokenTtlSeconds: Number(process.env.REFRESH_TOKEN_TTL_SECONDS ?? 60 * 60 * 24 * 14)
};

export const isProduction = config.env === 'production';
