/** zUSDC is 6-decimal and 1:1 with USDC (≈$1 via the vault). Formats base units as dollars, 2 decimals. */
export function formatUsd(units: bigint): string {
  const whole = units / 10n ** 6n;
  const cents = (units % 10n ** 6n) / 10n ** 4n;
  return `$${Number(whole).toLocaleString('en-US')}.${cents.toString().padStart(2, '0')}`;
}

/** "25" / "25.50" → 6-decimal base units. Throws on malformed input. */
export function parseUsd(input: string): bigint {
  const t = input.trim();
  if (!/^\d+(\.\d{0,2})?$/.test(t)) throw new Error('Enter an amount like 25 or 25.50');
  const [w, f = ''] = t.split('.');
  return BigInt(w) * 10n ** 6n + BigInt((f + '00').slice(0, 2)) * 10n ** 4n;
}
