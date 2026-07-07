import crypto from 'node:crypto';
import { exportJWK, importSPKI, jwtVerify, SignJWT, type JWK } from 'jose';
import { config } from '../config.js';

const generatedKeys =
  config.jwtPrivateKeyPem && config.jwtPublicKeyPem
    ? null
    : crypto.generateKeyPairSync('rsa', {
        modulusLength: 3072,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });

const privateKey = config.jwtPrivateKeyPem ?? generatedKeys!.privateKey;
const publicKey = config.jwtPublicKeyPem ?? generatedKeys!.publicKey;

const keyId = 'demo-rs256-key-1';
const privateKeyObject = crypto.createPrivateKey(privateKey);
const publicKeyObject = crypto.createPublicKey(publicKey);
const publicKeyLike = await importSPKI(publicKey, 'RS256');

export type AccessTokenClaims = {
  sub: string;
  client_id: string;
  scope: string;
  role: string;
};

export async function signAccessToken(claims: AccessTokenClaims): Promise<string> {
  return new SignJWT({
    client_id: claims.client_id,
    scope: claims.scope,
    role: claims.role
  })
    .setProtectedHeader({ alg: 'RS256', kid: keyId, typ: 'at+jwt' })
    .setIssuer(config.issuer)
    .setAudience(config.audience)
    .setSubject(claims.sub)
    .setIssuedAt()
    .setExpirationTime(`${config.accessTokenTtlSeconds}s`)
    .sign(privateKeyObject);
}

export async function verifyAccessToken(token: string) {
  // This defeats JWT alg-confusion by never trusting the token's alg header.
  // The validator pins: public RSA key + allowed algorithm + issuer + audience + typ.
  const { payload, protectedHeader } = await jwtVerify(token, publicKeyLike, {
    algorithms: ['RS256'],
    issuer: config.issuer,
    audience: config.audience,
    typ: 'at+jwt'
  });

  if (protectedHeader.kid !== keyId) {
    throw new Error('Unknown key id');
  }

  return payload;
}

export async function getJwks(): Promise<{ keys: JWK[] }> {
  const jwk = await exportJWK(publicKeyObject);
  return {
    keys: [
      {
        ...jwk,
        kid: keyId,
        alg: 'RS256',
        use: 'sig'
      }
    ]
  };
}
