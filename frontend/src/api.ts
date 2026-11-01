export interface SigningRequest {
  id: string;
  ts: number;
  chain: string;
  wallet: string;
  kind: string; // 'transfer' | 'contract_call' | 'authorization_7702'
  asset: string;
  amount_usd: number;
  to?: string | null;
  delegate?: string | null;
  meta?: Record<string, any>;
}

export interface DecisionReason {
  rule: string;
  message?: string;
  [key: string]: any;
}

export interface Decision {
  request_id: string;
  action: 'allow' | 'hold' | 'deny';
  risk: number; // 0 - 100
  reasons: DecisionReason[];
  breaker_state: 'Normal' | 'Elevated' | 'Hold' | 'Lockdown' | string;
}

export interface StepEvent {
  request_id: string;
  ts: number;
  chain: string;
  wallet: string;
  kind: string;
  amount_usd: number;
  scenario: string; // 'normal' | 'attack'
  unprotected_action: string;
  protected_decision: Decision;
  cumulative_unprotected_loss_usd: number;
  cumulative_protected_loss_usd: number;
}

export interface ReplayMetrics {
  total_requests: number;
  normal_requests_count: number;
  attack_requests_count: number;
  unprotected_loss_usd: number;
  protected_loss_usd: number;
  loss_prevented_usd: number;
  loss_prevented_pct: number;
  time_to_contain_seconds: number;
  seconds_to_first_block: number;
  first_blocked_event: Record<string, any> | null;
  breaker_lockdown_ts: number | null;
  breaker_lockdown_event_id: string | null;
  breaker_final_state: string;
  false_positive_count: number;
}

export interface ReplayResponse {
  summary: ReplayMetrics;
  steps: StepEvent[];
  results: Decision[];
  breaker_state: string;
  total_evaluated: number;
  allowed_count: number;
  held_count: number;
  denied_count: number;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  breaker_state: string;
}

export interface PolicyOverrides {
  single_tx_usd?: number;
  wallet_limit_usd?: number;
  global_limit_usd?: number;
  new_recipient_usd?: number;
  window_seconds?: number;
  spray_threshold?: number;
  [key: string]: any;
}

export interface Type4Finding {
  tx_hash: string;
  block_number: number;
  from_address?: string | null;
  to_address?: string | null;
  delegate_address?: string | null;
  unique_delegates_count: number;
  auth_count: number;
  has_consecutive_nonces: boolean;
  max_consecutive_nonces: number;
  patterns: string[];
  risk_score: number;
  is_suspicious: boolean;
  timestamp: number;
  source: string;
  description?: string | null;
}

export interface RadarScanResult {
  source: string; // 'live_rpc' | 'cached_sample' | 'cached_fallback'
  blocks_scanned: number;
  latest_block: number;
  findings_count: number;
  suspicious_count: number;
  findings: Type4Finding[];
}

export interface SensitivityPoint {
  limit_multiplier: number;
  single_tx_usd: number;
  wallet_limit_usd: number;
  global_limit_usd: number;
  new_recipient_usd: number;
  unprotected_loss_usd: number;
  protected_loss_usd: number;
  loss_prevented_usd: number;
  loss_mitigated_pct: number;
  false_positives_held: number;
  time_to_contain_seconds: number;
  breaker_final_state: string;
}

export interface SensitivityResponse {
  matrix: SensitivityPoint[];
  base_limits: Record<string, any>;
}

const API_BASE = '/api';

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw new Error(`Failed to fetch health status: ${res.statusText}`);
  }
  return res.json();
}

export async function evaluateSigningRequest(request: SigningRequest): Promise<Decision> {
  const res = await fetch(`${API_BASE}/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (!res.ok) {
    throw new Error(`Evaluation failed: ${res.statusText}`);
  }
  return res.json();
}

export async function runReplay(params?: {
  events?: SigningRequest[];
  policy_overrides?: PolicyOverrides;
}): Promise<ReplayResponse> {
  const res = await fetch(`${API_BASE}/replay`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params || {}),
  });
  if (!res.ok) {
    throw new Error(`Replay failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchRadar(params?: {
  n_blocks?: number;
  force_cached?: boolean;
}): Promise<RadarScanResult> {
  const n_blocks = params?.n_blocks ?? 5;
  const force_cached = params?.force_cached ?? false;
  const url = `${API_BASE}/radar?n_blocks=${n_blocks}&force_cached=${force_cached}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Radar scan failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSensitivityMatrix(params?: {
  base_limits?: PolicyOverrides;
  multipliers?: number[];
}): Promise<SensitivityResponse> {
  const res = await fetch(`${API_BASE}/policy/sensitivity`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params || {}),
  });
  if (!res.ok) {
    throw new Error(`Sensitivity calculation failed: ${res.statusText}`);
  }
  return res.json();
}

export async function resetSystem(): Promise<{ status: string; breaker_state: string }> {
  const res = await fetch(`${API_BASE}/reset`, {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`Reset failed: ${res.statusText}`);
  }
  return res.json();
}
