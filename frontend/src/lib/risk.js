// Risk presentation helpers. Thresholds mirror the backend defaults
// (WARN_THRESHOLD=50, URGENT_THRESHOLD=75) so the UI and the API agree on what
// "warning" means. If you change them in the backend .env, change them here too.

export const WARN_THRESHOLD = 50;
export const URGENT_THRESHOLD = 75;

export function riskLevel(score) {
  if (score >= URGENT_THRESHOLD) return 'critical';
  if (score >= WARN_THRESHOLD) return 'warning';
  if (score >= 30) return 'caution';
  if (score >= 15) return 'low';
  return 'safe';
}

// Risk = a semantic STATUS ramp (green→amber→orange→red = increasing severity).
// It is always shown alongside a text label + icon (never colour alone), which is
// what the status-colour rule requires and what makes it readable to a colour-blind
// user and an anxious victim alike.
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

// Node-type palette for the fraud graph.
//
// Identifier types use a CVD-validated categorical palette (normal-vision ΔE ≥ 16;
// green↔orange sits in the 6–8 CVD band, which is sound here because every node is
// also directly labelled with its value, legended, sized, and spatially clustered —
// colour is a secondary cue, not the sole channel).
//
// Sessions are NOT a category — they are the hubs. They get a neutral bright and
// render larger, which is exactly what let the categorical palette drop to five
// separable hues. Claimed name/department are muted on purpose: they never create
// cross-victim links, so they should recede.
const NODE_COLORS = {
  session: '#dbe4f0', // neutral bright hub
  phone: '#ea7317',
  upi: '#1eb85a',
  bank_account: '#dc2657',
  case_number: '#9d4edd',
  url: '#0e9fc0',
  claimed_name: '#8792a8', // recedes by design
  claimed_department: '#5a6478', // recedes by design
};

export function nodeColor(type) {
  return NODE_COLORS[type] || '#9aa7bd';
}

export const NODE_TYPE_LABELS = {
  session: 'Victim session',
  phone: 'Phone number',
  upi: 'UPI ID',
  bank_account: 'Bank account',
  case_number: 'Case number',
  url: 'Website',
  claimed_name: 'Claimed name',
  claimed_department: 'Claimed agency',
};

// Identifier types that create cross-victim links (mirrors the backend's
// LINKABLE_TYPES). Used to visually emphasise the nodes that actually matter.
export const LINKABLE_TYPES = new Set(['phone', 'upi', 'bank_account', 'case_number', 'url']);

// The coercion "kill chain" — the stages a digital-arrest scam moves through.
// The backend returns escalation_stage; naming where a live call sits on this
// script is what lets us warn before the extraction step, and it is a view no
// single-conversation detector offers.
export const ESCALATION_STAGES = [
  { key: 'pretext_established', short: 'Pretext', icon: '📋', desc: 'A cover story is set up' },
  { key: 'authority_asserted', short: 'Authority', icon: '🎖', desc: 'Official power claimed' },
  { key: 'fear_induced', short: 'Fear', icon: '⚠', desc: 'Threats & fake cases deployed' },
  { key: 'victim_isolated', short: 'Isolation', icon: '🔒', desc: 'Cut off from family' },
  { key: 'extraction_attempted', short: 'Extraction', icon: '💸', desc: 'Money or credentials demanded' },
];

// Index of the current stage within ESCALATION_STAGES; -1 means no contact risk yet.
export function stageIndex(stage) {
  if (!stage || stage === 'no_contact_risk') return -1;
  return ESCALATION_STAGES.findIndex((s) => s.key === stage);
}

export function prettyCategory(cat) {
  return (cat || '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export const SCAM_TYPE_LABELS = {
  digital_arrest: 'Digital Arrest',
  kyc_fraud: 'KYC Fraud',
  lottery_prize: 'Lottery / Prize',
  loan_fraud: 'Loan Fraud',
  job_scam: 'Job Scam',
  investment_fraud: 'Investment Fraud',
  tech_support: 'Tech Support',
  other_scam: 'Other Scam',
  none: 'No Scam Detected',
};

export function scamTypeLabel(t) {
  return SCAM_TYPE_LABELS[t] || prettyCategory(t);
}
