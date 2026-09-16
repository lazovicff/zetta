/** zDAI is 18-decimal and 1:1 with DAI (≈$1 via the vault). Formats wei as dollars, 2 decimals. */
export function formatUsd(wei: bigint): string {
  const whole = wei / 10n ** 18n;
  const cents = (wei % 10n ** 18n) / 10n ** 16n;
  return `$${Number(whole).toLocaleString('en-US')}.${cents.toString().padStart(2, '0')}`;
}

/** "25" / "25.50" → wei (18 decimals). Throws on malformed input. */
export function parseUsd(input: string): bigint {
  const t = input.trim();
  if (!/^\d+(\.\d{0,2})?$/.test(t)) throw new Error('Enter an amount like 25 or 25.50');
  const [w, f = ''] = t.split('.');
  return BigInt(w) * 10n ** 18n + BigInt((f + '00').slice(0, 2)) * 10n ** 16n;
}
