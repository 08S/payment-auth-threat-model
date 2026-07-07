import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { timingSafeEqualString } from './random.js';

const scryptAsync = promisify(crypto.scrypt);
const KEY_LENGTH = 64;

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const [salt, expected] = storedHash.split(':');
  if (!salt || !expected) return false;

  const derived = (await scryptAsync(password, salt, KEY_LENGTH)) as Buffer;
  return timingSafeEqualString(derived.toString('base64url'), expected);
}
