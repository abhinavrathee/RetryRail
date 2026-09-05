export function formatMoney(subunits: number, currency: string): string {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(subunits / 100);
}

export function formatPercentPpm(ppm: number): string {
  return `${(ppm / 10_000).toFixed(1)}%`;
}

export function formatBasisPoints(basisPoints: number): string {
  return `${(basisPoints / 100).toFixed(2)} pp`;
}

export function formatDateTime(value: string | null): string {
  if (value === null) return 'Not available';
  return new Intl.DateTimeFormat('en-IN', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export function humanize(value: string): string {
  return value.replaceAll('_', ' ').replace(/\b\w/gu, (letter) => letter.toUpperCase());
}
