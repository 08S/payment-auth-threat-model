import session from 'express-session';
import { config, isProduction } from '../config.js';

export const sessionMiddleware = session({
  name: isProduction ? '__Host-pay.sid' : 'pay.sid',
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: 1000 * 60 * 30
  }
});
