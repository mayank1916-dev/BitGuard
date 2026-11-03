/**
 * BitGuard Unified API Client Layer (Milestone U1 / F19 / F10).
 *
 * Exposes a unified client interface for both Demo Simulation mode ('demo')
 * and Live Backend API mode ('api') across:
 * - login
 * - evaluate(tx)
 * - getDecisions(filters)
 * - getBreaker()
 * - escalateBreaker(targetState, reason)
 * - getHolds()
 * - approve(holdId, assertion) with WebAuthn
 * - openStream(onEvent) with automatic reconnect & exponential backoff
 *
 * HARD CONSTRAINT:
 * Existing demo behavior remains 100% identical when DATA_SOURCE='demo'.
 * Zero CSS, layout, markup structure, or font changes.
 */

// =========================================================================
// DATA SOURCE CONFIGURATION
// =========================================================================

export type DataSource = 'demo' | 'api';

/**
 * Resolves the active data source with priority:
 * 1. URL Query Parameter: ?datasource=api | ?data_source=api | ?DATA_SOURCE=api
 * 2. LocalStorage: 'DATA_SOURCE'
 * 3. Vite Environment: VITE_DATA_SOURCE
 * 4. Default fallback: 'demo' (built-in simulation behavior preserved)
 */
export function getDataSource(): DataSource {
  if (typeof window !== 'undefined') {
    try {
      const params = new URLSearchParams(window.location.search);
      const queryVal = params.get('datasource') || params.get('data_source') || params.get('DATA_SOURCE');
      if (queryVal) {
        const lower = queryVal.toLowerCase().trim();
        if (lower === 'api' || lower === 'demo') {
          return lower as DataSource;
        }
      }
      const localVal = localStorage.getItem('DATA_SOURCE');
      if (localVal) {
        const lower = localVal.toLowerCase().trim();
        if (lower === 'api' || lower === 'demo') {
          return lower as DataSource;
        }
      }
      if ((window as any).__BITGUARD_DATA_SOURCE__) {
        const globalVal = String((window as any).__BITGUARD_DATA_SOURCE__).toLowerCase().trim();
        if (globalVal === 'api' || globalVal === 'demo') {
          return globalVal as DataSource;
        }
      }
    } catch {
      // In restricted environments, fall back to default
    }
  }

  // Vite environment fallback
  const envVal = (import.meta as any)?.env?.VITE_DATA_SOURCE;
  if (envVal === 'api' || envVal === 'demo') {
    return envVal as DataSource;
  }

  return 'demo';
}

export function setDataSource(source: DataSource): void {
  if (typeof window !== 'undefined') {
    try {
      localStorage.setItem('DATA_SOURCE', source);
    } catch {
      // Ignore in private browsing mode
    }
  }
}

export const DATA_SOURCE: DataSource = getDataSource();

// In-memory token storage for session authentication
let _activeAuthToken: string | null = null;

export function getActiveAuthToken(): string | null {
  if (_activeAuthToken) return _activeAuthToken;
  if (typeof window !== 'undefined') {
    try {
      return localStorage.getItem('bitguard_access_token');
    } catch {
      return null;
    }
  }
  return null;
}

export function setActiveAuthToken(token: string | null): void {
  _activeAuthToken = token;
  if (typeof window !== 'undefined') {
    try {
      if (token) {
        localStorage.setItem('bitguard_access_token', token);
      } else {
        localStorage.removeItem('bitguard_access_token');
      }
    } catch {
      // Ignore in private browsing mode
    }
  }
}

// =========================================================================
// DATA MODELS & INTERFACES (Full Backward Compatibility)
// =========================================================================

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
  raw_tx?: string;
  intent_id?: string;
}

export interface DecisionReason {
  rule: string;
  code?: string;
  weight?: number;
  message?: string;
  detail?: string;
  [key: string]: any;
}

export interface Decision {
  request_id: string;
  action: 'allow' | 'hold' | 'deny';
  risk: number; // 0 - 100
  reasons: DecisionReason[];
  breaker_state: 'Normal' | 'Elevated' | 'Hold' | 'Lockdown' | string;
  verdict?: 'ALLOW' | 'HOLD' | 'DENY';
  mode?: string;
  data_label?: 'REAL' | 'SYNTHETIC' | 'REPORTED';
  signature?: string;
  tx_hash?: string;
  hold_id?: string;
}

export interface StepEvent {
  request_id: string;
  ts: number;
  chain: string;
  wallet: string;
  kind: string;
  asset?: string;
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
  mode?: string;
  token_epoch?: number;
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
  source: string;
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
  multiplier?: number;
  effective_single_tx_cap?: number;
  capital_saved_usd?: number;
  mitigated_pct?: number;
  false_positives_count?: number;
  breaker_state?: string;
}

export interface SensitivityResponse {
  matrix: SensitivityPoint[];
  base_limits: Record<string, any>;
}

export interface SensitivityRequestParams {
  base_limits?: PolicyOverrides;
  multipliers?: number[];
  base_single_tx_usd?: number;
  base_wallet_limit_usd?: number;
  base_global_limit_usd?: number;
  base_new_recipient_usd?: number;
  [key: string]: any;
}

export interface AuditRecord {
  index: number;
  timestamp: number;
  request_id: string;
  action: 'allow' | 'hold' | 'deny';
  risk: number;
  rule_hits: string[];
  prev_hash: string;
  entry_hash: string;
  seq?: number;
  actor?: string;
  payload?: Record<string, any>;
}

export interface AuditChainResponse {
  root_hash: string;
  total_records: number;
  records: AuditRecord[];
}

export interface AuditVerifyResponse {
  valid: boolean;
  corrupted_index: number | null;
  root_hash: string;
  total_records: number;
  ok?: boolean;
  first_bad_seq?: number | null;
  checked_entries?: number;
}

export interface WebAuthnAssertionPayload {
  credential_id: string;
  client_data_json: string;
  authenticator_data: string;
  signature: string;
  user_handle?: string | null;
}

export interface ApprovalRecordItem {
  id: string;
  hold_ticket_id: string;
  approver_id: string;
  approver_role: string;
  tx_digest: string;
  webauthn_signature: string;
  assertion_data?: Record<string, any>;
  created_at: string;
}

export interface HoldTicketItem {
  id: string;
  request_id: string;
  tx_digest: string;
  raw_tx?: string;
  chain: string;
  wallet?: string;
  amount_usd: number;
  requester_id?: string;
  risk_score: number;
  reasons: Array<{ code: string; weight: number; detail: string }>;
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | string;
  expires_at: string;
  created_at: string;
  approvals: ApprovalRecordItem[];
  signed_result?: Record<string, any>;
  data_label: string;
}

export interface DecodedTxCall {
  to: string;
  value: number;
  selector: string;
  contract_type: string;
  method_name: string;
  is_unlimited_approval?: boolean;
}

export interface DecodedTxData {
  chain: string;
  tx_type: number;
  nonce: number;
  from_address: string;
  to_address?: string;
  value: number;
  digest: string;
  calls: DecodedTxCall[];
  authorizations?: Array<{ chain_id: number; address: string; nonce: number }>;
}

export interface HoldViewResponse {
  hold_id: string;
  request_id: string;
  status: string;
  tx_digest: string;
  raw_tx: string;
  chain: string;
  wallet?: string;
  amount_usd: number;
  requester_id?: string;
  risk_score: number;
  reasons: Array<{ code: string; weight: number; detail: string }>;
  decoded_tx?: DecodedTxData;
  seconds_remaining: number;
  is_expired: boolean;
  approvals: ApprovalRecordItem[];
  signed_result?: Record<string, any>;
  data_label: string;
}

export interface ApproveHoldResponse {
  status: 'PENDING_QUORUM' | 'RELEASED';
  hold_id: string;
  request_id: string;
  approvals_count: number;
  required_approvals: number;
  signature?: string;
  tx_hash?: string;
  message: string;
  data_label: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  role: string;
  user_id: string;
}

export interface BreakerStatusResponse {
  state: 'NORMAL' | 'ELEVATED' | 'HOLD' | 'LOCKDOWN' | string;
  mode?: string;
  token_epoch?: number;
  triggers?: any[];
  last_transition?: string;
}

// Default API Prefix
const API_BASE = '/api';

function getAuthHeaders(explicitToken?: string): Record<string, string> {
  const token = explicitToken || getActiveAuthToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

// =========================================================================
// TASK U1 REQUIRED SEAM FUNCTIONS
// =========================================================================

/**
 * 1. login(role, userId)
 * Authenticates user and caches the JWT for subsequent API requests.
 */
export async function login(role: string = 'Approver', userId?: string): Promise<LoginResponse> {
  if (DATA_SOURCE === 'demo') {
    const mockToken: LoginResponse = {
      access_token: `demo-jwt-${role.toLowerCase()}-${Date.now()}`,
      token_type: 'Bearer',
      role,
      user_id: userId || `usr-${role.toLowerCase()}-01`,
    };
    setActiveAuthToken(mockToken.access_token);
    return mockToken;
  }

  // Live API Mode: Obtain token from /v1/auth/dev-token
  const res = await fetch(`${API_BASE}/v1/auth/dev-token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role, user_id: userId }),
  });
  if (!res.ok) {
    throw new Error(`Login failed (${res.status}): ${res.statusText}`);
  }
  const data = await res.json();
  const loginResult: LoginResponse = {
    access_token: data.access_token,
    token_type: data.token_type || 'Bearer',
    role,
    user_id: userId || `usr-${role.toLowerCase()}-01`,
  };
  setActiveAuthToken(loginResult.access_token);
  return loginResult;
}

/**
 * 2. evaluate(tx)
 * Evaluates a transaction signing request against BitGuard firewall policies.
 */
export async function evaluate(tx: SigningRequest | any): Promise<Decision> {
  if (DATA_SOURCE === 'demo') {
    return evaluateSigningRequest(tx);
  }

  // Live API Mode: Query BitGuard /api/evaluate or /rpc
  const res = await fetch(`${API_BASE}/evaluate`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(tx),
  });
  if (!res.ok) {
    throw new Error(`Evaluation request failed: ${res.statusText}`);
  }
  const raw = await res.json();
  return {
    request_id: raw.request_id || tx.id || `req-${Date.now()}`,
    action: (raw.action || (raw.verdict ? raw.verdict.toLowerCase() : 'deny')) as 'allow' | 'hold' | 'deny',
    risk: raw.risk ?? raw.risk_score ?? 0,
    reasons: raw.reasons || [],
    breaker_state: raw.breaker_state || 'Normal',
    verdict: raw.verdict || (raw.action ? (raw.action.toUpperCase() as any) : 'DENY'),
    mode: raw.mode || 'ENFORCE',
    data_label: raw.data_label || 'REAL',
    signature: raw.signature,
    tx_hash: raw.tx_hash,
    hold_id: raw.hold_id,
  };
}

/**
 * 3. getDecisions(filters)
 * Retrieves historical or filtered signing decisions.
 */
export async function getDecisions(filters?: {
  limit?: number;
  cursor?: string;
  verdict?: string;
  wallet?: string;
  chain?: string;
  from_time?: number;
  to_time?: number;
}): Promise<{ decisions: Decision[]; next_cursor: string | null; total_count?: number }> {
  if (DATA_SOURCE === 'demo') {
    // Built-in demo simulation decisions fallback
    const res = await fetchHealth().catch(() => ({ breaker_state: 'Normal' }));
    return {
      decisions: [
        {
          request_id: 'demo-req-001',
          action: 'allow',
          risk: 12,
          reasons: [{ rule: 'WITHDRAWAL_APPROVED', message: 'Legitimate withdrawal within limits' }],
          breaker_state: res.breaker_state || 'Normal',
          verdict: 'ALLOW',
          data_label: 'SYNTHETIC',
        },
      ],
      next_cursor: null,
      total_count: 1,
    };
  }

  // Live API Mode: Query GET /v1/decisions
  const q = new URLSearchParams();
  if (filters?.limit) q.set('limit', String(filters.limit));
  if (filters?.cursor) q.set('cursor', filters.cursor);
  if (filters?.verdict) q.set('verdict', filters.verdict);
  if (filters?.wallet) q.set('wallet', filters.wallet);
  if (filters?.chain) q.set('chain', filters.chain);
  if (filters?.from_time) q.set('from_time', String(filters.from_time));
  if (filters?.to_time) q.set('to_time', String(filters.to_time));

  const url = `${API_BASE}/v1/decisions${q.toString() ? `?${q.toString()}` : ''}`;
  const res = await fetch(url, { headers: getAuthHeaders() });
  if (!res.ok) {
    throw new Error(`Failed to fetch decisions: ${res.statusText}`);
  }
  const data = await res.json();
  const decisionsList = Array.isArray(data) ? data : data.decisions || [];
  return {
    decisions: decisionsList.map((d: any) => ({
      request_id: d.request_id || d.id,
      action: (d.action || (d.verdict ? d.verdict.toLowerCase() : 'allow')) as 'allow' | 'hold' | 'deny',
      risk: d.risk ?? d.risk_score ?? 0,
      reasons: d.reasons || [],
      breaker_state: d.breaker_state || 'Normal',
      verdict: d.verdict,
      mode: d.mode,
      data_label: d.data_label || 'REAL',
    })),
    next_cursor: data.next_cursor || null,
    total_count: data.total_count ?? decisionsList.length,
  };
}

/**
 * 4. getBreaker()
 * Reads the active circuit breaker state.
 */
export async function getBreaker(): Promise<BreakerStatusResponse> {
  if (DATA_SOURCE === 'demo') {
    const health = await fetchHealth().catch(() => ({ breaker_state: 'Normal' }));
    return {
      state: health.breaker_state || 'Normal',
      mode: 'ENFORCE',
      token_epoch: 1,
      triggers: [],
    };
  }

  // Live API Mode: Query GET /v1/breaker
  const res = await fetch(`${API_BASE}/v1/breaker`, { headers: getAuthHeaders() });
  if (!res.ok) {
    throw new Error(`Failed to fetch breaker state: ${res.statusText}`);
  }
  return res.json();
}

/**
 * 5. escalateBreaker(targetState, reason)
 * Immediately escalates circuit breaker to higher state (asymmetric tightening).
 */
export async function escalateBreaker(
  targetState: string = 'LOCKDOWN',
  reason: string = 'Manual escalation from console'
): Promise<{ status: string; new_breaker_state: string; reason: string }> {
  if (DATA_SOURCE === 'demo') {
    return {
      status: 'escalated',
      new_breaker_state: targetState,
      reason,
    };
  }

  // Live API Mode: POST /v1/breaker/escalate
  const res = await fetch(`${API_BASE}/v1/breaker/escalate`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ target_state: targetState, reason }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Escalation failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * 6. getHolds()
 * Lists quarantined hold tickets pending review.
 */
export async function getHolds(): Promise<HoldTicketItem[]> {
  if (DATA_SOURCE === 'demo') {
    // Return sample hold ticket for demo interaction
    return [
      {
        id: 'ht-demo-001',
        request_id: 'req-demo-hold',
        tx_digest: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        raw_tx: '0xf86c808504a817c800825208941111111111111111111111111111111111111111880de0b6b3a7640000801ba0',
        chain: 'ethereum',
        wallet: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
        amount_usd: 75000.0,
        requester_id: 'spiffe://exchange.internal/workload/custody',
        risk_score: 65,
        reasons: [{ code: 'SINGLE_TX_LIMIT_EXCEEDED', weight: 65, detail: 'Exceeds single transaction threshold' }],
        status: 'PENDING',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        created_at: new Date().toISOString(),
        approvals: [],
        data_label: 'SYNTHETIC',
      },
    ];
  }

  return fetchActiveHolds();
}

/**
 * 7. approve(holdId, assertion)
 * Approves a quarantined hold ticket with a WebAuthn assertion signature over tx_digest.
 */
export async function approve(
  holdId: string,
  assertion?: WebAuthnAssertionPayload
): Promise<ApproveHoldResponse> {
  if (DATA_SOURCE === 'demo') {
    return {
      status: 'RELEASED',
      hold_id: holdId,
      request_id: `req-released-${holdId}`,
      approvals_count: 2,
      required_approvals: 2,
      signature: '0x' + 'ab'.repeat(65),
      tx_hash: '0x' + 'cd'.repeat(32),
      message: 'Quorum reached. Transaction signed and released to network (Demo Mode).',
      data_label: 'SYNTHETIC',
    };
  }

  // If assertion not provided, synthesize a developer test assertion or prompt hardware
  let finalAssertion = assertion;
  if (!finalAssertion) {
    finalAssertion = {
      credential_id: 'dev-virtual-credential-id',
      client_data_json: btoa(JSON.stringify({ type: 'webauthn.get', challenge: 'hold-digest', origin: window.location.origin })),
      authenticator_data: 'dev-auth-data',
      signature: 'dev-signature',
      user_handle: 'usr-approver-01',
    };
  }

  const token = getActiveAuthToken() || (await login('Approver')).access_token;
  return submitHoldApproval(holdId, finalAssertion, token);
}

/**
 * 8. openStream(onEvent)
 * Opens an event stream pushing real-time decisions, breaker state changes, and outflow metrics.
 * Implements robust exponential backoff with jitter and automatic reconnection.
 * Returns an unsubscribe cleanup callback: () => void.
 */
export function openStream(onEvent: (event: any) => void): () => void {
  let isClosed = false;
  let socket: WebSocket | null = null;
  let reconnectTimer: any = null;
  let simulatedTimer: any = null;
  let backoffMs = 1000;
  const maxBackoffMs = 15000;

  if (DATA_SOURCE === 'demo') {
    // In demo mode: provide periodic live feed updates without requiring backend websocket
    let seq = 1;
    simulatedTimer = setInterval(() => {
      if (isClosed) return;
      onEvent({
        type: 'DECISION_EVALUATED',
        payload: {
          seq: seq++,
          ts: Date.now(),
          verdict: 'ALLOW',
          risk_score: Math.floor(Math.random() * 20) + 5,
          wallet: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
          chain: 'ethereum',
          amount_usd: 1200 + Math.floor(Math.random() * 500),
          data_label: 'SYNTHETIC',
        },
        data_label: 'SYNTHETIC',
      });
    }, 5000);

    return () => {
      isClosed = true;
      if (simulatedTimer) clearInterval(simulatedTimer);
    };
  }

  const connect = () => {
    if (isClosed) return;

    try {
      const token = getActiveAuthToken() || '';
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/v1/stream?token=${encodeURIComponent(token)}`;

      socket = new WebSocket(wsUrl);

      socket.onopen = () => {
        // Reset backoff on successful connection
        backoffMs = 1000;
      };

      socket.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          onEvent(parsed);
        } catch (err) {
          console.warn('[BitGuard Stream] Failed to parse message JSON:', err);
        }
      };

      socket.onerror = (err) => {
        console.warn('[BitGuard Stream] WebSocket error observed:', err);
      };

      socket.onclose = () => {
        socket = null;
        if (!isClosed) {
          // Calculate jittered exponential backoff
          const jitter = (Math.random() * 0.4 - 0.2) * backoffMs;
          const delay = Math.min(maxBackoffMs, Math.max(500, backoffMs + jitter));
          backoffMs = Math.min(maxBackoffMs, backoffMs * 1.5);

          reconnectTimer = setTimeout(() => {
            connect();
          }, delay);
        }
      };
    } catch (err) {
      console.warn('[BitGuard Stream] Socket instantiation failed, scheduling retry:', err);
      if (!isClosed) {
        reconnectTimer = setTimeout(connect, backoffMs);
      }
    }
  };

  connect();

  return () => {
    isClosed = true;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (simulatedTimer) clearInterval(simulatedTimer);
    if (socket) {
      socket.close();
      socket = null;
    }
  };
}

// =========================================================================
// EXISTING SIMULATION & DASHBOARD CALLS (Kept for Full Compatibility)
// =========================================================================

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
  const url = `${API_BASE}/radar?n_blocks=${n_blocks}&force_cached=${force_cached}&_t=${Date.now()}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Radar scan failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSensitivityMatrix(params?: SensitivityRequestParams): Promise<SensitivityResponse> {
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

export async function fetchAuditRecords(): Promise<AuditChainResponse> {
  const res = await fetch(`${API_BASE}/audit/records`);
  if (!res.ok) {
    throw new Error(`Failed to fetch audit records: ${res.statusText}`);
  }
  return res.json();
}

export async function verifyAuditIntegrity(): Promise<AuditVerifyResponse> {
  const res = await fetch(`${API_BASE}/audit/verify`);
  if (!res.ok) {
    throw new Error(`Failed to verify audit chain: ${res.statusText}`);
  }
  return res.json();
}

export async function simulateAuditTamper(index?: number): Promise<any> {
  const url = index !== undefined ? `${API_BASE}/audit/simulate-tamper?index=${index}` : `${API_BASE}/audit/simulate-tamper`;
  const res = await fetch(url, { method: 'POST' });
  if (!res.ok) {
    throw new Error(`Failed to simulate tamper: ${res.statusText}`);
  }
  return res.json();
}

export async function resetAuditChain(): Promise<AuditVerifyResponse> {
  const res = await fetch(`${API_BASE}/audit/reset`, { method: 'POST' });
  if (!res.ok) {
    throw new Error(`Failed to reset audit chain: ${res.statusText}`);
  }
  return res.json();
}

export function getReportDownloadUrl(): string {
  return `${API_BASE}/report/download`;
}

export async function fetchDevToken(role: string = 'Approver', user_id?: string): Promise<string> {
  const res = await fetch(`${API_BASE}/v1/auth/dev-token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role, user_id }),
  });
  if (!res.ok) {
    throw new Error(`Dev token fetch failed: ${res.statusText}`);
  }
  const data = await res.json();
  return data.access_token;
}

export async function fetchActiveHolds(token?: string): Promise<HoldTicketItem[]> {
  const headers: Record<string, string> = {};
  const activeToken = token || getActiveAuthToken();
  if (activeToken) headers['Authorization'] = `Bearer ${activeToken}`;
  const res = await fetch(`${API_BASE}/v1/holds`, { headers });
  if (!res.ok) {
    throw new Error(`Failed to fetch holds: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchHoldView(holdId: string, token?: string): Promise<HoldViewResponse> {
  const headers: Record<string, string> = {};
  const activeToken = token || getActiveAuthToken();
  if (activeToken) headers['Authorization'] = `Bearer ${activeToken}`;
  const res = await fetch(`${API_BASE}/v1/holds/${holdId}/view`, { headers });
  if (!res.ok) {
    throw new Error(`Failed to fetch hold view: ${res.statusText}`);
  }
  return res.json();
}

export async function submitHoldApproval(
  holdId: string,
  assertion: WebAuthnAssertionPayload,
  token: string
): Promise<ApproveHoldResponse> {
  const res = await fetch(`${API_BASE}/v1/holds/${holdId}/approve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ assertion }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Approval failed: ${res.statusText}`);
  }
  return res.json();
}

export async function denyHold(
  holdId: string,
  reason: string,
  token: string
): Promise<{ status: string; hold_id: string; reason: string }> {
  const res = await fetch(`${API_BASE}/v1/holds/${holdId}/deny`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ reason }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Denial failed: ${res.statusText}`);
  }
  return res.json();
}
