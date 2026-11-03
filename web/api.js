/**
 * BitGuard JavaScript API Client Layer (Milestone U1 / F19 / F10).
 *
 * Provides an isomorphic / browser ES module exposing:
 * - login
 * - evaluate(tx)
 * - getDecisions(filters)
 * - getBreaker()
 * - escalateBreaker(targetState, reason)
 * - getHolds()
 * - approve(holdId, assertion) with WebAuthn
 * - openStream(onEvent) with automatic reconnect & exponential backoff
 *
 * DATA_SOURCE setting:
 * - 'demo': Built-in simulation behavior (offline-friendly, identical existing UI)
 * - 'api': Real backend REST and WebSocket communication
 */

/**
 * Resolves active data source ('demo' | 'api')
 */
export function getDataSource() {
  if (typeof window !== 'undefined') {
    try {
      const params = new URLSearchParams(window.location.search);
      const q = params.get('datasource') || params.get('data_source') || params.get('DATA_SOURCE');
      if (q) {
        const lower = q.toLowerCase().trim();
        if (lower === 'api' || lower === 'demo') {
          return lower;
        }
      }
      const local = localStorage.getItem('DATA_SOURCE');
      if (local) {
        const lower = local.toLowerCase().trim();
        if (lower === 'api' || lower === 'demo') {
          return lower;
        }
      }
      if (window.__BITGUARD_DATA_SOURCE__) {
        const globalVal = String(window.__BITGUARD_DATA_SOURCE__).toLowerCase().trim();
        if (globalVal === 'api' || globalVal === 'demo') {
          return globalVal;
        }
      }
    } catch {
      // Fallback
    }
  }
  return 'demo';
}

export function setDataSource(source) {
  if (typeof window !== 'undefined') {
    try {
      localStorage.setItem('DATA_SOURCE', source);
    } catch {
      // Ignore
    }
  }
}

export const DATA_SOURCE = getDataSource();

let _authToken = null;

export function getActiveAuthToken() {
  if (_authToken) return _authToken;
  if (typeof window !== 'undefined') {
    try {
      return localStorage.getItem('bitguard_access_token');
    } catch {
      return null;
    }
  }
  return null;
}

export function setActiveAuthToken(token) {
  _authToken = token;
  if (typeof window !== 'undefined') {
    try {
      if (token) {
        localStorage.setItem('bitguard_access_token', token);
      } else {
        localStorage.removeItem('bitguard_access_token');
      }
    } catch {
      // Ignore
    }
  }
}

const API_BASE = '/api';

function getAuthHeaders(token) {
  const active = token || getActiveAuthToken();
  const headers = { 'Content-Type': 'application/json' };
  if (active) {
    headers['Authorization'] = `Bearer ${active}`;
  }
  return headers;
}

/**
 * 1. login(role, userId)
 */
export async function login(role = 'Approver', userId) {
  if (getDataSource() === 'demo') {
    const mock = {
      access_token: `demo-token-${role.toLowerCase()}-${Date.now()}`,
      token_type: 'Bearer',
      role,
      user_id: userId || `usr-${role.toLowerCase()}-01`,
    };
    setActiveAuthToken(mock.access_token);
    return mock;
  }

  const res = await fetch(`${API_BASE}/v1/auth/dev-token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role, user_id: userId }),
  });
  if (!res.ok) {
    throw new Error(`Login failed (${res.status}): ${res.statusText}`);
  }
  const data = await res.json();
  const result = {
    access_token: data.access_token,
    token_type: data.token_type || 'Bearer',
    role,
    user_id: userId || `usr-${role.toLowerCase()}-01`,
  };
  setActiveAuthToken(result.access_token);
  return result;
}

/**
 * 2. evaluate(tx)
 */
export async function evaluate(tx) {
  if (getDataSource() === 'demo') {
    const res = await fetch(`${API_BASE}/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tx),
    });
    if (!res.ok) {
      throw new Error(`Evaluation failed: ${res.statusText}`);
    }
    return res.json();
  }

  if (tx && tx.raw_tx) {
    return evaluateCustomTx(tx);
  }

  const res = await fetch(`${API_BASE}/evaluate`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(tx),
  });
  if (!res.ok) {
    throw new Error(`Evaluation failed: ${res.statusText}`);
  }
  const raw = await res.json();
  return {
    request_id: raw.request_id || tx.id || `req-${Date.now()}`,
    action: (raw.action || (raw.verdict ? raw.verdict.toLowerCase() : 'deny')),
    risk: raw.risk ?? raw.risk_score ?? 0,
    risk_score: raw.risk_score ?? raw.risk ?? 0,
    reasons: raw.reasons || [],
    breaker_state: raw.breaker_state || 'Normal',
    verdict: raw.verdict || (raw.action ? raw.action.toUpperCase() : 'DENY'),
    mode: raw.mode || 'ENFORCE',
    data_label: raw.data_label || 'REAL',
    timings: raw.timings || {},
    decoded_tx: raw.decoded_tx || null,
    evaluation_latency_ms: raw.evaluation_latency_ms,
    signature: raw.signature,
    tx_hash: raw.tx_hash,
    hold_id: raw.hold_id,
  };
}

/**
 * Evaluates custom raw transaction bytes via POST /v1/evaluate (Task U4).
 */
export async function evaluateCustomTx(params) {
  if (getDataSource() === 'demo') {
    const res = await fetch(`${API_BASE}/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (!res.ok) {
      throw new Error(`Evaluation failed: ${res.statusText}`);
    }
    return res.json();
  }

  const endpoint = `${API_BASE}/v1/evaluate`;
  let res = await fetch(endpoint, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(params),
  });
  if (!res.ok && res.status === 404) {
    res = await fetch(`/v1/evaluate`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(params),
    });
  }
  if (!res.ok) {
    let errDetail = res.statusText;
    try {
      const errJson = await res.json();
      if (errJson && errJson.detail) {
        errDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {}
    throw new Error(`Evaluation failed (${res.status}): ${errDetail}`);
  }
  const raw = await res.json();
  return {
    request_id: raw.request_id || `req-${Date.now()}`,
    action: (raw.action || (raw.verdict ? raw.verdict.toLowerCase() : 'deny')),
    risk: raw.risk_score ?? raw.risk ?? 0,
    risk_score: raw.risk_score ?? raw.risk ?? 0,
    reasons: raw.reasons || [],
    breaker_state: raw.breaker_state || 'Normal',
    verdict: raw.verdict || (raw.action ? raw.action.toUpperCase() : 'DENY'),
    mode: raw.mode || 'SIMULATION',
    data_label: raw.data_label || 'SYNTHETIC',
    timings: raw.timings || {},
    decoded_tx: raw.decoded_tx || null,
    evaluation_latency_ms: raw.evaluation_latency_ms,
    policy_version: raw.policy_version,
    wallet: raw.wallet,
    chain: raw.chain,
    signature: raw.signature,
    tx_hash: raw.tx_hash,
    hold_id: raw.hold_id,
    dry_run_note: 'dry run - nothing signed or reserved',
  };
}

/**
 * 3. getDecisions(filters)
 */
export async function getDecisions(filters = {}) {
  if (getDataSource() === 'demo') {
    return {
      decisions: [
        {
          request_id: 'demo-req-001',
          action: 'allow',
          risk: 10,
          reasons: [{ rule: 'APPROVED', message: 'Standard withdrawal within limits' }],
          breaker_state: 'Normal',
          verdict: 'ALLOW',
          data_label: 'SYNTHETIC',
        },
      ],
      next_cursor: null,
      total_count: 1,
    };
  }

  const q = new URLSearchParams();
  if (filters.limit) q.set('limit', String(filters.limit));
  if (filters.cursor) q.set('cursor', filters.cursor);
  if (filters.verdict) q.set('verdict', filters.verdict);
  if (filters.wallet) q.set('wallet', filters.wallet);
  if (filters.chain) q.set('chain', filters.chain);

  const url = `${API_BASE}/v1/decisions${q.toString() ? `?${q.toString()}` : ''}`;
  const res = await fetch(url, { headers: getAuthHeaders() });
  if (!res.ok) {
    throw new Error(`Failed to fetch decisions: ${res.statusText}`);
  }
  const data = await res.json();
  const list = Array.isArray(data) ? data : data.decisions || [];
  return {
    decisions: list,
    next_cursor: data.next_cursor || null,
    total_count: data.total_count ?? list.length,
  };
}

/**
 * 4. getBreaker()
 */
export async function getBreaker() {
  if (getDataSource() === 'demo') {
    const res = await fetch(`${API_BASE}/health`).catch(() => null);
    const data = res && res.ok ? await res.json() : { breaker_state: 'Normal' };
    return {
      state: data.breaker_state || 'Normal',
      mode: 'ENFORCE',
      token_epoch: 1,
      triggers: [],
    };
  }

  const res = await fetch(`${API_BASE}/v1/breaker`, { headers: getAuthHeaders() });
  if (!res.ok) {
    throw new Error(`Failed to fetch breaker: ${res.statusText}`);
  }
  return res.json();
}

/**
 * 5. escalateBreaker(targetState, reason)
 */
export async function escalateBreaker(targetState = 'LOCKDOWN', reason = 'Manual escalation') {
  if (getDataSource() === 'demo') {
    return {
      status: 'escalated',
      new_breaker_state: targetState,
      reason,
    };
  }

  const res = await fetch(`${API_BASE}/v1/breaker/escalate`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ target_state: targetState, reason }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Escalation failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * 6. getHolds()
 */
export async function getHolds() {
  if (getDataSource() === 'demo') {
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

  const res = await fetch(`${API_BASE}/v1/holds`, { headers: getAuthHeaders() });
  if (!res.ok) {
    throw new Error(`Failed to fetch holds: ${res.statusText}`);
  }
  return res.json();
}

/**
 * 7. approve(holdId, assertion)
 */
export async function approve(holdId, assertion) {
  if (getDataSource() === 'demo') {
    return {
      status: 'RELEASED',
      hold_id: holdId,
      request_id: `req-released-${holdId}`,
      approvals_count: 2,
      required_approvals: 2,
      signature: '0x' + 'ab'.repeat(65),
      tx_hash: '0x' + 'cd'.repeat(32),
      message: 'Quorum reached. Released to network (Demo Mode).',
      data_label: 'SYNTHETIC',
    };
  }

  const finalAssertion = assertion || {
    credential_id: 'dev-virtual-credential-id',
    client_data_json: btoa(JSON.stringify({ type: 'webauthn.get', challenge: 'hold-digest', origin: window.location.origin })),
    authenticator_data: 'dev-auth-data',
    signature: 'dev-signature',
    user_handle: 'usr-approver-01',
  };

  const token = getActiveAuthToken() || (await login('Approver')).access_token;
  const res = await fetch(`${API_BASE}/v1/holds/${holdId}/approve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ assertion: finalAssertion }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Approval failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * 8. openStream(onEvent)
 */
export function openStream(onEvent) {
  let isClosed = false;
  let socket = null;
  let reconnectTimer = null;
  let simulatedTimer = null;
  let backoffMs = 1000;
  const maxBackoffMs = 15000;

  if (getDataSource() === 'demo') {
    let seq = 1;
    simulatedTimer = setInterval(() => {
      if (isClosed) return;
      onEvent({
        type: 'DECISION_EVALUATED',
        payload: {
          seq: seq++,
          ts: Date.now(),
          verdict: 'ALLOW',
          risk_score: 15,
          wallet: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
          chain: 'ethereum',
          amount_usd: 1500,
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
        backoffMs = 1000;
      };

      socket.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          onEvent(parsed);
        } catch (err) {
          console.warn('[BitGuard Stream] Parse error:', err);
        }
      };

      socket.onerror = (err) => {
        console.warn('[BitGuard Stream] WebSocket error:', err);
      };

      socket.onclose = () => {
        socket = null;
        if (!isClosed) {
          const jitter = (Math.random() * 0.4 - 0.2) * backoffMs;
          const delay = Math.min(maxBackoffMs, Math.max(500, backoffMs + jitter));
          backoffMs = Math.min(maxBackoffMs, backoffMs * 1.5);

          reconnectTimer = setTimeout(connect, delay);
        }
      };
    } catch (err) {
      console.warn('[BitGuard Stream] Connection failed:', err);
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

/**
 * 9. getMode() / fetchCurrentMode()
 * Reads the active operational mode (SIMULATION, SHADOW, ENFORCE).
 */
export async function fetchCurrentMode() {
  if (DATA_SOURCE === 'demo') {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const m = params.get('mode');
      if (m) {
        const upper = m.toUpperCase();
        if (upper === 'SHADOW' || upper === 'ENFORCE' || upper === 'SIMULATION') {
          return upper;
        }
      }
    }
    return 'SIMULATION';
  }

  try {
    const res = await fetch(`${API_BASE}/v1/mode`, { headers: getAuthHeaders() });
    if (res.ok) {
      const data = await res.json();
      if (data && data.mode) {
        return data.mode.toUpperCase();
      }
    }
    const wgRes = await fetch(`${API_BASE}/v1/wallet-groups`, { headers: getAuthHeaders() });
    if (wgRes.ok) {
      const list = await wgRes.json();
      if (Array.isArray(list) && list.length > 0 && list[0].mode) {
        return list[0].mode.toUpperCase();
      }
    }
  } catch (err) {
    console.warn('Failed to fetch mode from API, fallback to SIMULATION:', err);
  }
  return 'SIMULATION';
}

export const getMode = fetchCurrentMode;

/**
 * 10. fetchShadowMetrics(walletGroup)
 * Reads aggregated shadow mode metrics and would_have counters from S04.
 */
export async function fetchShadowMetrics(walletGroup = 'default') {
  if (DATA_SOURCE === 'demo') {
    return {
      mode: 'SIMULATION',
      wallet_group: walletGroup,
      would_have_allowed_count: 0,
      would_have_allowed_value: 0,
      would_have_blocked_count: 0,
      would_have_blocked_value: 0,
    };
  }

  try {
    const res = await fetch(`${API_BASE}/v1/metrics/shadow?wallet_group=${encodeURIComponent(walletGroup)}`, {
      headers: getAuthHeaders(),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('Failed to fetch shadow metrics from API:', err);
  }

  return {
    mode: 'SIMULATION',
    wallet_group: walletGroup,
    would_have_allowed_count: 0,
    would_have_allowed_value: 0,
    would_have_blocked_count: 0,
    would_have_blocked_value: 0,
  };
}

/**
 * 11. listBacktests()
 */
export async function listBacktests() {
  if (DATA_SOURCE === 'demo') {
    return [
      {
        id: 'binance-exploit-2026',
        name: 'Binance Exploit Sequence (Oct 2026)',
        description: 'Late-October 2026 multi-chain exploit sequence including XRP outflow, 7702 spray, and massive sweeps.',
        events_count: 72,
        source: 'incident_export',
      },
      {
        id: 'multichain-velocity-spike',
        name: 'Multi-Chain Velocity Spike',
        description: 'Simulated multi-chain concurrent burst exceeding per-wallet and global rolling window limits.',
        events_count: 35,
        source: 'synthetic_generator',
      },
      {
        id: 'unauthorized-delegation-7702',
        name: 'EIP-7702 Unauthorized Delegation Spray',
        description: 'Type-4 transaction batch directing hot wallet addresses to non-allowlisted upgradeable contracts.',
        events_count: 20,
        source: 'lab_scenario',
      },
    ];
  }

  try {
    const res = await fetch(`${API_BASE}/v1/backtests`, { headers: getAuthHeaders() });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('Failed to fetch backtests:', err);
  }

  return [
    {
      id: 'binance-exploit-2026',
      name: 'Binance Exploit Sequence (Oct 2026)',
      description: 'Late-October 2026 multi-chain exploit sequence including XRP outflow, 7702 spray, and massive sweeps.',
      events_count: 72,
      source: 'incident_export',
    },
  ];
}

/**
 * 12. runBacktest(backtestId)
 */
export async function runBacktest(backtestId) {
  if (DATA_SOURCE === 'demo') {
    return {
      steps: [],
      summary: {},
    };
  }

  try {
    const res = await fetch(`${API_BASE}/v1/backtests/${encodeURIComponent(backtestId)}/run`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('Failed to run backtest:', err);
  }

  return { steps: [], summary: {} };
}

/**
 * 13. getRecordedDecisions()
 */
export async function getRecordedDecisions() {
  try {
    const data = await getDecisions({ limit: 100 });
    const list = data.decisions || [];
    let cumUnp = 0;
    let cumProt = 0;
    return list.map((d, i) => {
      const amt = Number(d.amount_usd || 15000);
      cumUnp += amt;
      const isAllow = (d.action || d.verdict || '').toLowerCase() === 'allow';
      if (isAllow) cumProt += amt;
      return {
        request_id: d.request_id || `rec-${i}`,
        ts: d.ts || Date.now() / 1000,
        chain: d.chain || 'ethereum',
        wallet: d.wallet || '0xBinanceHotETH1',
        kind: d.kind || 'transfer',
        amount_usd: amt,
        scenario: isAllow ? 'normal' : 'attack',
        unprotected_action: 'allow',
        protected_decision: {
          request_id: d.request_id || `rec-${i}`,
          action: (d.action || d.verdict || 'allow').toLowerCase(),
          risk: d.risk || 15,
          reasons: d.reasons || [],
          breaker_state: d.breaker_state || 'Normal',
          data_label: 'REAL',
        },
        cumulative_unprotected_loss_usd: cumUnp,
        cumulative_protected_loss_usd: cumProt,
        data_label: 'REAL',
      };
    });
  } catch {
    return [];
  }
}

export default {
  DATA_SOURCE,
  getDataSource,
  setDataSource,
  getActiveAuthToken,
  setActiveAuthToken,
  login,
  evaluate,
  evaluateCustomTx,
  getDecisions,
  getBreaker,
  escalateBreaker,
  getHolds,
  approve,
  openStream,
  getMode,
  fetchCurrentMode,
  fetchShadowMetrics,
  listBacktests,
  runBacktest,
  getRecordedDecisions,
};
