// Display-only card artifacts. PAN/CVC are STUBS derived deterministically
// from the order ref — real ones come from a card provider, not this app.

import type { CardOrderRow } from './api';

/** 3y from order placement — display convention, mirrors the old CreateCardSheet. */
const CARD_LIFETIME_MS = 3 * 365 * 24 * 3600 * 1000;

function refDigits(ref: string, count: number): string {
  let h = 2166136261 >>> 0;
  let out = '';
  while (out.length < count) {
    for (const ch of ref) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0;
    out += String(h % 10);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return out;
}

/** Deterministic stub PAN: '4' + 15 digits. */
export function cardNumber(ref: string): string {
  return '4' + refDigits(ref, 15);
}

export function cardCvc(ref: string): string {
  return refDigits(ref + '#cvc', 3);
}

export function cardCreatedMs(order: CardOrderRow): number {
  return order.created_at * 1000;
}

export function cardExpiry(createdMs: number): Date {
  return new Date(createdMs + CARD_LIFETIME_MS);
}
