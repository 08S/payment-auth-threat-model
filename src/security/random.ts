import crypto from 'node:crypto';

export function randomBase64Url(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256Base64Url(input: string): string {
  return crypto.createHash('sha256').update(input).digest('base64url');
}

export function timingSafeEqualString(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);

  if (aBuffer.length !== bBuffer.length) return false;
  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

export function hashSecret(secret: string): string {
  // A fast hash is acceptable for random high-entropy tokens.
  // Passwords must use Argon2/bcrypt/scrypt instead.
  return crypto.createHash('sha256').update(secret).digest('hex');
}
