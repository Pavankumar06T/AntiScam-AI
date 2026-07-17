// Risk presentation helpers. Thresholds mirror the backend defaults
// (WARN_THRESHOLD=50, URGENT_THRESHOLD=75) so the UI and the API agree on what
// "warning" means. If you change them in the backend .env, change them here too.

export const WARN_THRESHOLD = 50;
export const URGENT_THRESHOLD = 75;

export function riskLevel(score) {
  if (score >= URGENT_THRESHOLD) return 'critical';
  if (score >= WARN_THRESHOLD) return 'warning';
  if (score >= 30) return 'caution';
  return 'safe';
}

export function riskColor(score) {
  if (score >= URGENT_THRESHOLD) return 'var(--risk-critical)';
  if (score >= WARN_THRESHOLD) return 'var(--risk-warn)';
  if (score >= 30) return 'var(--risk-caution)';
  if (score >= 15) return 'var(--risk-low)';
  return 'var(--risk-safe)';
}

export function riskLabel(score) {
  if (score >= URGENT_THRESHOLD) return 'Critical Risk';
  if (score >= WARN_THRESHOLD) return 'High Risk';
  if (score >= 30) return 'Suspicious';
  if (score >= 15) return 'Low Risk';
  return 'No Risk Detected';
}

const NODE_COLORS = {
  session: '#6366f1',
  phone: '#f97316',
  upi: '#22c55e',
  bank_account: '#ef4444',
  claimed_name: '#a855f7',
  claimed_department: '#64708a',
  case_number: '#eab308',
  url: '#06b6d4',
};

export function nodeColor(type) {
  return NODE_COLORS[type] || '#9aa7bd';
}

export const NODE_TYPE_LABELS = {
  session: 'Victim session',
  phone: 'Phone number',
  upi: 'UPI ID',
  bank_account: 'Bank account',
  claimed_name: 'Claimed name',
  claimed_department: 'Claimed agency',
  case_number: 'Case number',
  url: 'Website',
};

export function prettyCategory(cat) {
  return (cat || '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}
