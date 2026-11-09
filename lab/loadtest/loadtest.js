import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

// Custom metrics
const fastPathLatency = new Trend('fast_path_duration_ms');
const signingPathLatency = new Trend('signing_path_duration_ms');
const errorRate = new Rate('loadtest_errors');

export const options = {
  scenarios: {
    // Stage 1: 50 concurrent virtual users
    concurrency_50: {
      executor: 'constant-vus',
      vus: 50,
      duration: '5m',
      startTime: '0s',
      tags: { concurrency: '50' },
    },
    // Stage 2: 200 concurrent virtual users
    concurrency_200: {
      executor: 'constant-vus',
      vus: 200,
      duration: '5m',
      startTime: '5m',
      tags: { concurrency: '200' },
    },
    // Stage 3: 500 concurrent virtual users
    concurrency_500: {
      executor: 'constant-vus',
      vus: 500,
      duration: '5m',
      startTime: '10m',
      tags: { concurrency: '500' },
    },
  },
  thresholds: {
    // Target p99 under 15 ms, measured for the local fast path
    'fast_path_duration_ms{concurrency:50}': ['p(95)<10', 'p(99)<15'],
    'fast_path_duration_ms{concurrency:200}': ['p(95)<12', 'p(99)<15'],
    'loadtest_errors': ['rate<0.01'],
  },
};

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8000';

// Canonical raw unsigned EVM transaction payload
const SAMPLE_RAW_TX = '0x04f870808504a817c8008252089411111111111111111111111111111111111111118203e880c0';
const OWNED_WALLET = '0x742d35Cc6634C0532925a3b844Bc454e4438f44e';

export default function () {
  const vuId = __VU;
  const iteration = __ITER;

  // 1. Fast Path: POST /v1/evaluate
  const evalPayload = JSON.stringify({
    id: `eval-${vuId}-${iteration}`,
    chain: 'ethereum',
    raw_tx: SAMPLE_RAW_TX,
    wallet: OWNED_WALLET,
    wallet_group: 'default',
    mode: 'SIMULATION',
    metadata: {
      amount_usd: 50.0,
      caller_identity: `worker-${vuId}`,
    },
  });

  const evalParams = {
    headers: {
      'Content-Type': 'application/json',
      'X-Dev-Role': 'operator',
      'X-Caller-ID': `client-${vuId}`,
    },
    tags: { name: 'FastPathEvaluate' },
  };

  const evalRes = http.post(`${BASE_URL}/v1/evaluate`, evalPayload, evalParams);
  const evalOk = check(evalRes, {
    'fast path status is 200': (r) => r.status === 200,
    'verdict is present': (r) => r.json('verdict') !== undefined,
  });

  if (evalOk) {
    fastPathLatency.add(evalRes.timings.duration);
    errorRate.add(0);
  } else {
    errorRate.add(1);
  }

  // 2. End-to-End Signing Path: POST /rpc
  const rpcPayload = JSON.stringify({
    jsonrpc: '2.0',
    method: 'bitguard_signTransaction',
    params: {
      chain: 'ethereum',
      raw_tx: SAMPLE_RAW_TX,
      amount_usd: 10.0,
      metadata: {
        caller_identity: `spiffe://exchange.internal/workload/custody-${vuId % 20}`,
      },
    },
    id: `rpc-${vuId}-${iteration}`,
  });

  const rpcParams = {
    headers: {
      'Content-Type': 'application/json',
      'X-Client-Cert-SAN': `spiffe://exchange.internal/workload/custody-${vuId % 20}`,
    },
    tags: { name: 'SigningPathRpc' },
  };

  const rpcRes = http.post(`${BASE_URL}/rpc`, rpcPayload, rpcParams);
  const rpcOk = check(rpcRes, {
    'signing path status is 200': (r) => r.status === 200,
  });

  if (rpcOk) {
    signingPathLatency.add(rpcRes.timings.duration);
    errorRate.add(0);
  } else {
    errorRate.add(1);
  }

  sleep(0.005);
}
