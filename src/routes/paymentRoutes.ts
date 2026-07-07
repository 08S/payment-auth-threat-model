import crypto from 'node:crypto';
import type { Response, Router } from 'express';
import express from 'express';
import { z } from 'zod';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import { requireAccessToken, requireScope } from '../middleware/auth.js';

export const paymentRoutes: Router = express.Router();

const paymentCreateSchema = z.object({
  orderId: z.string().min(3).max(128)
});

const payments = new Map<string, { paymentId: string; ownerUserId: string; orderId: string; amount: number; currency: string; status: string }>([
  ['pay_demo_123', { paymentId: 'pay_demo_123', ownerUserId: 'user_123', orderId: 'order_demo_123', amount: 1500, currency: 'INR', status: 'AUTHORIZED' }]
]);

const idempotencyKeys = new Map<string, string>();

paymentRoutes.get('/payments/:paymentId', requireAccessToken, requireScope('payments:read'), (req: AuthenticatedRequest, res: Response) => {
  const paymentId = String(req.params.paymentId);
  const payment = payments.get(paymentId);
  if (!payment || payment.ownerUserId !== req.auth?.sub) {
    return res.status(404).json({ error: 'payment_not_found' });
  }

  return res.json(payment);
});

paymentRoutes.post('/payments', requireAccessToken, requireScope('payments:create'), (req: AuthenticatedRequest, res: Response) => {
  const idempotencyKey = req.header('idempotency-key');
  if (!idempotencyKey || idempotencyKey.length < 8 || idempotencyKey.length > 128) {
    return res.status(400).json({ error: 'missing_idempotency_key' });
  }

  const parsed = paymentCreateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_payment_payload' });

  const idempotencyOwnerKey = `${req.auth?.sub}:${idempotencyKey}`;
  const existingPaymentId = idempotencyKeys.get(idempotencyOwnerKey);
  if (existingPaymentId) {
    return res.status(200).json(payments.get(existingPaymentId));
  }

  const paymentId = `pay_${crypto.randomUUID()}`;
  const payment = {
    paymentId,
    ownerUserId: req.auth?.sub,
    orderId: parsed.data.orderId,
    amount: 1500,
    currency: 'INR',
    status: 'CREATED'
  };

  if (!payment.ownerUserId) return res.status(401).json({ error: 'invalid_access_token' });

  payments.set(paymentId, { ...payment, ownerUserId: payment.ownerUserId });
  idempotencyKeys.set(idempotencyOwnerKey, paymentId);

  return res.status(201).json(payment);
});
