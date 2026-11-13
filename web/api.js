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
export async function escalateBreaker(targetState = 'LOCKDOWN', reason = 'Manual escalation', explicitToken) {
  if (getDataSource() === 'demo') {
    return {
      status: 'escalated',
      new_breaker_state: targetState,
      reason,
    };
  }

  const res = await fetch(`${API_BASE}/v1/breaker/escalate`, {
    method: 'POST',
    headers: getAuthHeaders(explicitToken),
    body: JSON.stringify({ target_state: targetState, reason }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Escalation failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Creates a circuit breaker de-escalation proposal requiring 2-approver WebAuthn quorum.
 */
export async function createDeescalationRequest(
  targetState = 'NORMAL',
  reason = 'Investigation resolved; nominal operations safe to resume',
  explicitToken
) {
  if (getDataSource() === 'demo') {
    return {
      id: 'brk-req-demo-01',
      current_state: 'LOCKDOWN',
      target_state: targetState,
      reason,
      requested_by: 'usr-secops-01',
      challenge: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      status: 'PENDING',
      approvals: [],
      created_at: new Date().toISOString(),
      required_approvals: 2,
      data_label: 'SYNTHETIC',
    };
  }

  const res = await fetch(`${API_BASE}/v1/breaker/deescalate-request`, {
    method: 'POST',
    headers: getAuthHeaders(explicitToken),
    body: JSON.stringify({ target_state: targetState, reason }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `De-escalation request failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Submits a WebAuthn approval over the de-escalation challenge.
 */
export async function approveDeescalation(requestId, assertion, explicitToken) {
  if (getDataSource() === 'demo') {
    return {
      request_id: requestId,
      status: 'APPROVED',
      approvals_count: 2,
      required_approvals: 2,
      message: 'Quorum reached (2 of 2 in demo). Breaker de-escalated.',
      new_breaker_state: 'NORMAL',
      data_label: 'SYNTHETIC',
    };
  }

  const res = await fetch(`${API_BASE}/v1/breaker/deescalate-approve`, {
    method: 'POST',
    headers: getAuthHeaders(explicitToken),
    body: JSON.stringify({ request_id: requestId, assertion }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Approval failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Retrieves the currently active pending de-escalation request.
 */
export async function fetchActiveDeescalationRequest(explicitToken) {
  if (getDataSource() === 'demo') {
    return null;
  }

  const res = await fetch(`${API_BASE}/v1/breaker/deescalate-requests/active`, {
    headers: getAuthHeaders(explicitToken),
  });
  if (!res.ok) {
    if (res.status === 404) return null;
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch active de-escalation request: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Retrieves a de-escalation request by ID.
 */
export async function fetchDeescalationRequestById(requestId, explicitToken) {
  if (getDataSource() === 'demo') {
    throw new Error(`Demo mode request '${requestId}' not found`);
  }

  const res = await fetch(`${API_BASE}/v1/breaker/deescalate-requests/${requestId}`, {
    headers: getAuthHeaders(explicitToken),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch de-escalation request: ${res.statusText}`);
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
 * Retrieves active queued time-locked withdrawals (Milestone U5).
 */
export async function fetchTimelocks() {
  if (getDataSource() === 'demo') {
    return [
      {
        id: 'tl-req-001',
        request_id: 'req-timelock-large-01',
        chain: 'ethereum',
        wallet: '0xBinanceHotETH1',
        recipient: '0x3333333333333333333333333333333333333333',
        asset: 'ETH',
        amount_usd: 150000.0,
        status: 'QUEUED',
        release_time: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
        created_at: new Date().toISOString(),
        data_label: 'SYNTHETIC',
      },
      {
        id: 'tl-req-002',
        request_id: 'req-timelock-large-02',
        chain: 'tron',
        wallet: 'TBinanceHotTRX1',
        recipient: 'TAttackerTRONAddress0000000000000000',
        asset: 'USDT',
        amount_usd: 650000.0,
        status: 'QUEUED',
        release_time: new Date(Date.now() + 45 * 60 * 1000).toISOString(),
        created_at: new Date().toISOString(),
        data_label: 'SYNTHETIC',
      },
    ];
  }

  try {
    let res = await fetch(`${API_BASE}/v1/timelocks`, { headers: getAuthHeaders() });
    if (!res.ok) {
      res = await fetch(`/v1/timelocks`, { headers: getAuthHeaders() });
    }
    if (res.ok) {
      return res.json();
    }
  } catch (err) {
    console.warn('Failed to fetch timelocks:', err);
  }
  return [];
}

/**
 * Cancels a queued time-locked withdrawal (Milestone U5).
 */
export async function cancelTimelock(id, reason = 'Manual operator cancellation') {
  if (getDataSource() === 'demo') {
    return {
      id,
      request_id: 'req-cancelled',
      chain: 'ethereum',
      wallet: '0xBinanceHotETH1',
      recipient: '0x3333333333333333333333333333333333333333',
      asset: 'ETH',
      amount_usd: 150000.0,
      status: 'CANCELLED',
      release_time: new Date().toISOString(),
      created_at: new Date().toISOString(),
      data_label: 'SYNTHETIC',
      cancel_reason: reason,
    };
  }

  let res = await fetch(`${API_BASE}/v1/timelocks/${encodeURIComponent(id)}/cancel`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ reason }),
  });
  if (!res.ok && res.status === 404) {
    res = await fetch(`/v1/timelocks/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ reason }),
    });
  }
  if (!res.ok) {
    throw new Error(`Failed to cancel timelock: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Retrieves per-chain cumulative outflow aggregates (Milestone U5).
 */
export async function fetchChainOutflows() {
  if (getDataSource() === 'demo') {
    return {
      ethereum: 25000.0,
      bitcoin: 120000.0,
      solana: 45000.0,
      tron: 650000.0,
      arbitrum: 15000.0,
      base: 8500.0,
      optimism: 3200.0,
    };
  }

  try {
    let res = await fetch(`${API_BASE}/v1/outflows`, { headers: getAuthHeaders() });
    if (!res.ok) {
      res = await fetch(`/v1/outflows`, { headers: getAuthHeaders() });
    }
    if (res.ok) {
      const data = await res.json();
      return data.outflows || {};
    }
  } catch (err) {
    console.warn('Failed to fetch outflows:', err);
  }
  return {};
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

// In-memory mock store for demo mode
let demoWatchedAddresses = [
  {
    id: 'wa-demo-eth-01',
    address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    chain: 'ethereum',
    label: 'Primary Hot Wallet ETH-1',
    expected_code_hash: null,
    allowed_delegates: ['0x1111111111111111111111111111111111111111'],
    last_known_nonce: 42,
    signed_count: 12,
    last_scanned_block: 19854210,
    status: 'ACTIVE',
    data_label: 'SYNTHETIC',
    created_at: new Date(Date.now() - 86400000).toISOString(),
    delegation_state: 'none',
    delegate_address: null,
    delegate_code_hash: null,
    provider_agreement: 'all agree',
    recent_alerts: [],
  },
  {
    id: 'wa-demo-eth-02',
    address: '0x1234567890123456789012345678901234567890',
    chain: 'arbitrum',
    label: 'Arbitrum Gateway Staging Vault',
    expected_code_hash: null,
    allowed_delegates: ['0x2222222222222222222222222222222222222222'],
    last_known_nonce: 10,
    signed_count: 4,
    last_scanned_block: 19854210,
    status: 'ACTIVE',
    data_label: 'SYNTHETIC',
    created_at: new Date(Date.now() - 43200000).toISOString(),
    delegation_state: 'allowed delegate',
    delegate_address: '0x2222222222222222222222222222222222222222',
    delegate_code_hash: '0xc1d5b4ce3e2a6227293fccce2904121c8647bbe16c1216340b851bf12d12560e',
    provider_agreement: 'all agree',
    recent_alerts: [],
  },
  {
    id: 'wa-demo-eth-03',
    address: '0x9999999999999999999999999999999999999999',
    chain: 'ethereum',
    label: 'Attacker-Targeted Staging Hot Wallet',
    expected_code_hash: null,
    allowed_delegates: [],
    last_known_nonce: 99,
    signed_count: 1,
    last_scanned_block: 19854210,
    status: 'ACTIVE',
    data_label: 'SYNTHETIC',
    created_at: new Date(Date.now() - 3600000).toISOString(),
    delegation_state: 'UNAPPROVED',
    delegate_address: '0xBadC0deAttackerDelegate000000000000000000',
    delegate_code_hash: '0xdeadd00d6666666666666666666666666666666666666666666666666666666',
    provider_agreement: 'disagree',
    recent_alerts: [
      {
        id: 'alert-demo-7702-01',
        alert_code: 'UNAUTHORIZED_DELEGATION',
        severity: 'CRITICAL',
        address: '0x9999999999999999999999999999999999999999',
        chain: 'ethereum',
        block_number: 19854210,
        block_timestamp: Date.now() / 1000 - 15,
        detection_timestamp: Date.now() / 1000 - 14.992,
        latency_blocks: 0,
        latency_seconds: 0.008,
        details: {
          delegate: '0xBadC0deAttackerDelegate000000000000000000',
          message: 'EIP-7702 delegate code hash not allowlisted on monitored address',
        },
        breaker_tripped: true,
        data_label: 'SYNTHETIC',
      },
    ],
  },
];

/**
 * Lists all watched hot wallet addresses with delegation status and alerts.
 */
export async function fetchWatchedAddresses(explicitToken) {
  if (getDataSource() === 'demo') {
    return [...demoWatchedAddresses];
  }

  const res = await fetch(`${API_BASE}/v1/watched-addresses`, {
    headers: getAuthHeaders(explicitToken),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch watched addresses: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Registers a new internal hot wallet address for delegation monitoring (SecOps only).
 */
export async function createWatchedAddress(payload, explicitToken) {
  if (getDataSource() === 'demo') {
    const newItem = {
      id: `wa-demo-${Date.now()}`,
      address: payload.address,
      chain: payload.chain || 'ethereum',
      label: payload.label,
      expected_code_hash: payload.expected_code_hash || null,
      allowed_delegates: payload.allowed_delegates || [],
      last_known_nonce: payload.initial_nonce || 0,
      signed_count: 0,
      last_scanned_block: 19854210,
      status: 'ACTIVE',
      data_label: 'SYNTHETIC',
      created_at: new Date().toISOString(),
      delegation_state: 'none',
      delegate_address: null,
      delegate_code_hash: null,
      provider_agreement: 'all agree',
      recent_alerts: [],
    };
    demoWatchedAddresses = [newItem, ...demoWatchedAddresses];
    return newItem;
  }

  const res = await fetch(`${API_BASE}/v1/watched-addresses`, {
    method: 'POST',
    headers: getAuthHeaders(explicitToken),
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create watched address: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Removes an address from delegation watching (SecOps only).
 */
export async function deleteWatchedAddress(watchedId, explicitToken) {
  if (getDataSource() === 'demo') {
    demoWatchedAddresses = demoWatchedAddresses.filter((w) => w.id !== watchedId);
    return { status: 'deleted', id: watchedId };
  }

  const res = await fetch(`${API_BASE}/v1/watched-addresses/${watchedId}`, {
    method: 'DELETE',
    headers: getAuthHeaders(explicitToken),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete watched address: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Triggers an on-demand watcher scan across RPC nodes.
 */
export async function triggerWatcherScan(blockNumber, explicitToken) {
  if (getDataSource() === 'demo') {
    return demoWatchedAddresses.flatMap((w) => w.recent_alerts);
  }

  const url = blockNumber ? `${API_BASE}/v1/watcher/scan?block_number=${blockNumber}` : `${API_BASE}/v1/watcher/scan`;
  const res = await fetch(url, {
    method: 'POST',
    headers: getAuthHeaders(explicitToken),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Watcher scan failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Fetches recent security alerts detected by the watcher.
 */
export async function fetchWatcherAlerts(explicitToken) {
  if (getDataSource() === 'demo') {
    return demoWatchedAddresses.flatMap((w) => w.recent_alerts);
  }

  const res = await fetch(`${API_BASE}/v1/watcher/alerts`, {
    headers: getAuthHeaders(explicitToken),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch alerts: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Classifies a draft policy against the active baseline (Task U8).
 */
export async function classifyPolicy(draft, baselineVersionId) {
  if (getDataSource() === 'demo') {
    const singleTx = Number(draft?.single_tx_usd ?? 50_000);
    const walletLimit = Number(draft?.wallet_limit_usd ?? 100_000);
    const isTighten = singleTx <= 50_000 && walletLimit <= 100_000;
    const isLoosen = singleTx >= 50_000 && walletLimit >= 100_000 && (singleTx > 50_000 || walletLimit > 100_000);
    const badge = isTighten ? 'TIGHTENS' : isLoosen ? 'LOOSENS' : 'MIXED';
    return {
      classification: isTighten ? 'TIGHTEN' : isLoosen ? 'LOOSEN' : 'MIXED',
      badge,
      diff: {
        single_tx_usd: { old: 50000, new: singleTx, direction: singleTx > 50000 ? 'LOOSEN' : 'TIGHTEN' },
        wallet_limit_usd: { old: 100000, new: walletLimit, direction: walletLimit > 100000 ? 'LOOSEN' : 'TIGHTEN' },
      },
      text_diff: `--- active (v1.0.0)\n+++ draft\n- single_tx_usd: 50000\n+ single_tx_usd: ${singleTx}\n- wallet_limit_usd: 100000\n+ wallet_limit_usd: ${walletLimit}`,
      requirements: {
        approvers_required: isTighten ? 1 : 2,
        cooldown_seconds: isTighten ? 0 : 60,
        backtest_required: !isTighten,
        can_instant_activate: isTighten,
      },
      active_version: 'v1.0.0',
      active_id: 'pv-baseline-v1.0.0',
      draft_hash: '0x' + Array(64).fill('a').join(''),
    };
  }

  const res = await fetch(`${API_BASE}/v1/policies/classify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ draft, baseline_version_id: baselineVersionId }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Classification failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Runs S22 backtesting on a draft policy (Task U8).
 */
export async function runPolicyBacktest(draftPolicy, scenarios, explicitToken) {
  if (getDataSource() === 'demo') {
    return {
      id: `btr-demo-${Date.now().toString(36)}`,
      held_count: 5,
      holds_per_day: 1.2,
      estimated_false_positives: 1,
      synthetic_loss_prevented_usd: 4_390_000_000,
      synthetic_loss_allowed_usd: 0,
      total_events: 72,
      draft_policy_id: 'pv-demo-draft',
      draft_policy_hash: '0x' + Array(64).fill('b').join(''),
    };
  }

  const token = explicitToken || getActiveAuthToken() || (await login('Approver')).access_token;
  const res = await fetch(`${API_BASE}/v1/policies/draft/backtest`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ draft_policy: draftPolicy, scenarios: scenarios || ['split_under_limit', 'rapid_velocity'] }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Backtest failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Lists policy versions (Task U8).
 */
export async function listPolicies(limit = 50, explicitToken) {
  if (getDataSource() === 'demo') {
    return [
      {
        id: 'pv-baseline-v1.0.0',
        version: 'v1.0.0',
        author: 'admin@bitguard.local',
        created_at: new Date(Date.now() - 86400000 * 7).toISOString(),
        status: 'ACTIVE',
        content: {},
        content_hash: '0x' + Array(64).fill('0').join(''),
        change_type: 'TIGHTEN',
        approvals: [],
      },
    ];
  }

  const token = explicitToken || getActiveAuthToken() || (await login('Operator')).access_token;
  const res = await fetch(`${API_BASE}/v1/policies?limit=${limit}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to list policies: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Gets currently active policy (Task U8).
 */
export async function getActivePolicy(explicitToken) {
  if (getDataSource() === 'demo') {
    const list = await listPolicies(1);
    return list[0];
  }

  const token = explicitToken || getActiveAuthToken() || (await login('Operator')).access_token;
  const res = await fetch(`${API_BASE}/v1/policies/active`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to get active policy: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Proposes a new policy version (Task U8).
 */
export async function proposePolicy(payload, explicitToken) {
  const token = explicitToken || getActiveAuthToken() || (await login('Operator')).access_token;
  const res = await fetch(`${API_BASE}/v1/policies`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to propose policy: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Submits WebAuthn approval signature for policy (Task U8).
 */
export async function approvePolicy(versionId, assertion, explicitToken) {
  const defaultAssertion = assertion || {
    credential_id: 'cred-approver-fido2',
    client_data_json: btoa(JSON.stringify({ type: 'webauthn.get', challenge: 'policy-hash', origin: window.location.origin })),
    authenticator_data: btoa('auth-data-policy-sample'),
    signature: btoa('sig-sample-policy-webauthn'),
    user_handle: 'usr-approver-01',
  };

  const token = explicitToken || getActiveAuthToken() || (await login('Approver')).access_token;
  const res = await fetch(`${API_BASE}/v1/policies/${encodeURIComponent(versionId)}/approve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ assertion: defaultAssertion }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Policy approval failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Activates policy change (Task U8).
 */
export async function activatePolicy(versionId, explicitToken) {
  const token = explicitToken || getActiveAuthToken() || (await login('Operator')).access_token;
  const res = await fetch(`${API_BASE}/v1/policies/${encodeURIComponent(versionId)}/activate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({}),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Policy activation failed: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Rolls back policy to target version (Task U8).
 */
export async function rollbackPolicy(versionId, reason = 'Operator initiated rollback', explicitToken) {
  const token = explicitToken || getActiveAuthToken() || (await login('Admin')).access_token;
  const res = await fetch(`${API_BASE}/v1/policies/${encodeURIComponent(versionId)}/rollback`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ reason }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Policy rollback failed: ${res.statusText}`);
  }
  return res.json();
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
  fetchTimelocks,
  cancelTimelock,
  fetchChainOutflows,
  createDeescalationRequest,
  approveDeescalation,
  fetchActiveDeescalationRequest,
  fetchDeescalationRequestById,
  fetchWatchedAddresses,
  createWatchedAddress,
  deleteWatchedAddress,
  triggerWatcherScan,
  fetchWatcherAlerts,
  classifyPolicy,
  runPolicyBacktest,
  listPolicies,
  getActivePolicy,
  proposePolicy,
  approvePolicy,
  activatePolicy,
  rollbackPolicy,
};
