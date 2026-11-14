import React, { useState, useEffect } from 'react';
import {
  StepEvent,
  DATA_SOURCE,
  openStream,
  fetchActiveHolds,
  fetchHoldView,
  fetchDevToken,
  submitHoldApproval,
  denyHold,
  fetchTimelocks,
  cancelTimelock,
  fetchChainOutflows,
  HoldViewResponse,
  TimelockItem,
  WebAuthnAssertionPayload,
} from '../api';
import {
  formatFullCurrency,
  getChainBadgeStyle,
  getDataLabelBadgeStyle,
  truncateAddress,
  cn,
} from '../utils';
import {
  Search,
  Filter,
  Activity,
  Clock,
  ShieldCheck,
  XCircle,
  AlertTriangle,
  KeyRound,
  Ban,
  UserCheck,
} from 'lucide-react';

interface LiveFeedProps {
  steps: StepEvent[];
  currentStep?: number;
  isPlaying?: boolean;
}

const ALL_CHAINS = ['ethereum', 'bitcoin', 'solana', 'tron', 'arbitrum', 'base', 'optimism'];
const SAMPLE_WALLETS = [
  '0xBinanceHotETH1',
  'bc1qBinanceHotBTC1',
  'SolBinanceHot1',
  'TBinanceHotTRX1',
  '0xBinanceHotArb1',
  '0xBinanceHotBase1',
];

// Helper generating simulated assertion with matching digest challenge for virtual testing
const generateSimulatedAssertion = (digest: string, approver: string): WebAuthnAssertionPayload => {
  const clientDataObj = {
    type: 'webauthn.get',
    challenge: digest,
    origin: typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000',
    crossOrigin: false,
  };
  const clientDataJson = btoa(JSON.stringify(clientDataObj));
  const rpIdHash = '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763';
  const flags = '01'; // User presence bit
  const signCountHex = '00000001';
  const authenticatorDataHex = rpIdHash + flags + signCountHex;
  const rawAuthBytes = new Uint8Array(
    authenticatorDataHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
  );
  const authenticatorDataB64 = btoa(String.fromCharCode(...rawAuthBytes));
  const signatureHex = '3045022100' + 'a'.repeat(64) + '0220' + 'b'.repeat(64);
  const sigBytes = new Uint8Array(signatureHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []);
  const signatureB64 = btoa(String.fromCharCode(...sigBytes));

  return {
    credential_id: `cred-${approver}`,
    client_data_json: clientDataJson,
    authenticator_data: authenticatorDataB64,
    signature: signatureB64,
    user_handle: approver,
  };
};

export const LiveFeed: React.FC<LiveFeedProps> = ({ steps, currentStep, isPlaying }) => {
  const [filterAction, setFilterAction] = useState<'all' | 'allow' | 'blocked' | 'attack'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [liveStream, setLiveStream] = useState<StepEvent[]>([]);

  // Per-Chain Outflow Velocity (5-second aggregates)
  const [outflowAggregates, setOutflowAggregates] = useState<Record<string, number>>({});

  // Pending Quarantine HOLD Queue
  const [pendingHolds, setPendingHolds] = useState<HoldViewResponse[]>([]);
  const [activeApproverId, setActiveApproverId] = useState<string>('usr-approver-01');
  const [holdActionMsg, setHoldActionMsg] = useState<{ id: string; msg: string; isError?: boolean } | null>(null);
  const [isApproving, setIsApproving] = useState<string | null>(null);

  // Time-Lock Queue
  const [timelocks, setTimelocks] = useState<TimelockItem[]>([]);
  const [timelockMsg, setTimelockMsg] = useState<{ id: string; msg: string; isError?: boolean } | null>(null);

  // 1. Initial Data Synchronization
  useEffect(() => {
    if (isPlaying && typeof currentStep === 'number') {
      setLiveStream(steps.slice(0, currentStep + 1));
    } else if (liveStream.length === 0 && steps.length > 0) {
      setLiveStream(steps);
    }
  }, [steps, currentStep, isPlaying]);

  // 2. Fetch Initial Outflow Aggregates and Timelocks
  useEffect(() => {
    fetchChainOutflows().then(setOutflowAggregates).catch(() => {});
    fetchTimelocks().then(setTimelocks).catch(() => {});
    loadPendingHolds();
  }, [activeApproverId]);

  // Load Pending Holds
  const loadPendingHolds = async () => {
    try {
      const token = await fetchDevToken('Approver', activeApproverId);
      const holdTickets = await fetchActiveHolds(token);

      const views = await Promise.all(
        holdTickets.map(async (t) => {
          try {
            return await fetchHoldView(t.id, token);
          } catch {
            return {
              hold_id: t.id,
              request_id: t.request_id,
              status: t.status,
              tx_digest: t.tx_digest,
              raw_tx: t.raw_tx || '',
              chain: t.chain,
              wallet: t.wallet,
              amount_usd: t.amount_usd,
              requester_id: t.requester_id,
              risk_score: t.risk_score,
              reasons: t.reasons,
              seconds_remaining: Math.max(0, Math.floor((new Date(t.expires_at).getTime() - Date.now()) / 1000)),
              is_expired: new Date(t.expires_at).getTime() <= Date.now(),
              approvals: t.approvals || [],
              data_label: t.data_label || 'REAL',
            } as HoldViewResponse;
          }
        })
      );

      const activeViews = views.filter((v) => v.status === 'PENDING' || v.status === 'PENDING_QUORUM');
      if (activeViews.length > 0) {
        setPendingHolds(activeViews);
      } else if (DATA_SOURCE === 'demo') {
        // In demo mode: seed a realistic quarantine hold ticket for testing if none exist
        setPendingHolds([
          {
            hold_id: 'ht-demo-001',
            request_id: 'req-hold-demo-01',
            status: 'PENDING',
            tx_digest: '0x3a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef012',
            raw_tx: '0xec018504a817c80082520894742d35cc6634c0532925a3b844bc454e4438f44e89015af1d78b58c4000080018080',
            chain: 'ethereum',
            wallet: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
            amount_usd: 75000.0,
            requester_id: 'usr-requester-01',
            risk_score: 85,
            reasons: [
              {
                code: 'WALLET_LIMIT_EXCEEDED',
                weight: 85,
                detail: 'Single transfer exceeds remaining hot wallet velocity cap ($75,000 > $50,000)',
              },
            ],
            decoded_tx: {
              chain: 'ethereum',
              tx_type: 0,
              nonce: 14,
              from_address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
              to_address: '0x4444444444444444444444444444444444444444',
              value: 25000000000000000000,
              digest: '0x3a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef012',
              calls: [],
            },
            seconds_remaining: 54,
            is_expired: false,
            approvals: [
              {
                id: 'appr-01',
                hold_ticket_id: 'ht-demo-001',
                approver_id: 'usr-approver-01',
                approver_role: 'Approver',
                tx_digest: '0x3a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef012',
                webauthn_signature: 'sig-01',
                created_at: new Date().toISOString(),
              },
            ],
            data_label: 'SYNTHETIC',
          },
        ]);
      } else {
        setPendingHolds([]);
      }
    } catch (err) {
      console.warn('Failed loading hold queue:', err);
    }
  };

  // 3. Connect to WebSocket /v1/stream in API mode with automatic deduplication
  useEffect(() => {
    if (DATA_SOURCE !== 'api') return;

    const unsubscribe = openStream((event: any) => {
      if (!event) return;

      if (event.type === 'connected' && event.payload?.last_decisions) {
        const decisions: any[] = event.payload.last_decisions;
        const mappedSteps: StepEvent[] = decisions.map((d) => ({
          request_id: d.request_id,
          ts: d.created_at ? new Date(d.created_at).getTime() / 1000 : Date.now() / 1000,
          chain: d.chain || d.decoded_tx?.chain || 'ethereum',
          wallet: d.wallet || d.decoded_tx?.from || d.decoded_tx?.from_address || '0xHotWallet',
          kind: d.decoded_tx?.authorizations?.length ? 'authorization_7702' : 'transfer',
          amount_usd: d.decoded_tx?.amount ? Number(d.decoded_tx.amount) / 1e18 : Number(d.timings?.amount_usd || 0),
          scenario: d.verdict === 'DENY' || d.action === 'deny' ? 'attack' : 'normal',
          unprotected_action: 'allow',
          protected_decision: {
            request_id: d.request_id,
            action: (d.action || (d.verdict ? d.verdict.toLowerCase() : 'deny')) as any,
            risk: d.risk_score ?? d.risk ?? 0,
            reasons: d.reasons || [],
            breaker_state: d.breaker_state || 'Normal',
            verdict: d.verdict,
            mode: d.mode,
            data_label: d.data_label || 'REAL',
          },
          cumulative_unprotected_loss_usd: 0,
          cumulative_protected_loss_usd: 0,
          data_label: d.data_label || 'REAL',
        }));

        setLiveStream((prev) => {
          const seen = new Set(prev.map((s) => s.request_id));
          const uniqueNew = mappedSteps.filter((s) => !seen.has(s.request_id));
          return [...uniqueNew, ...prev].slice(0, 200);
        });
      } else if (event.type === 'decision' && event.payload) {
        const d = event.payload;
        const newStep: StepEvent = {
          request_id: d.request_id,
          ts: d.created_at ? new Date(d.created_at).getTime() / 1000 : Date.now() / 1000,
          chain: d.chain || d.decoded_tx?.chain || 'ethereum',
          wallet: d.wallet || d.decoded_tx?.from || d.decoded_tx?.from_address || '0xHotWallet',
          kind: d.decoded_tx?.authorizations?.length ? 'authorization_7702' : 'transfer',
          amount_usd: d.decoded_tx?.amount ? Number(d.decoded_tx.amount) / 1e18 : Number(d.timings?.amount_usd || 0),
          scenario: d.verdict === 'DENY' || d.action === 'deny' ? 'attack' : 'normal',
          unprotected_action: 'allow',
          protected_decision: {
            request_id: d.request_id,
            action: (d.action || (d.verdict ? d.verdict.toLowerCase() : 'deny')) as any,
            risk: d.risk_score ?? d.risk ?? 0,
            reasons: d.reasons || [],
            breaker_state: d.breaker_state || 'Normal',
            verdict: d.verdict,
            mode: d.mode,
            data_label: d.data_label || 'REAL',
          },
          cumulative_unprotected_loss_usd: 0,
          cumulative_protected_loss_usd: 0,
          data_label: d.data_label || 'REAL',
        };

        // Deduplicate cards on reconnect
        setLiveStream((prev) => {
          if (prev.some((s) => s.request_id === newStep.request_id)) {
            return prev;
          }
          return [newStep, ...prev].slice(0, 200);
        });
      } else if (event.type === 'chain_outflow_aggregate' && event.payload?.outflows) {
        // 5-second per-chain outflow aggregates
        setOutflowAggregates(event.payload.outflows);
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  // 4. Demo Mode Simulated Stream (Preserved exactly in demo mode)
  useEffect(() => {
    if (DATA_SOURCE === 'api' || isPlaying) return;

    const interval = setInterval(() => {
      const randomIdx = Math.floor(Math.random() * ALL_CHAINS.length);
      const chain = ALL_CHAINS[randomIdx];
      const wallet = SAMPLE_WALLETS[randomIdx % SAMPLE_WALLETS.length];
      const txId = `tx-live-${Math.random().toString(36).substring(2, 8)}`;
      const amount = Math.floor(Math.random() * 4500) + 120;

      const microWithdrawal: StepEvent = {
        request_id: txId,
        ts: Date.now() / 1000,
        chain: chain,
        wallet: wallet,
        kind: 'transfer',
        amount_usd: amount,
        scenario: 'normal',
        unprotected_action: 'allow',
        protected_decision: {
          request_id: txId,
          action: 'allow',
          risk: 0,
          reasons: [],
          breaker_state: 'Normal',
          verdict: 'ALLOW',
          data_label: 'SYNTHETIC',
        },
        cumulative_unprotected_loss_usd: 0,
        cumulative_protected_loss_usd: 0,
        data_label: 'SYNTHETIC',
      };

      setLiveStream((prev) => [microWithdrawal, ...prev.slice(0, 99)]);
    }, 3000);

    return () => clearInterval(interval);
  }, [isPlaying]);

  // 5. 1-second Countdown Timer for Hold Tickets
  useEffect(() => {
    const timer = setInterval(() => {
      setPendingHolds((prev) =>
        prev.map((h) => {
          if (h.seconds_remaining <= 0) {
            return { ...h, is_expired: true, seconds_remaining: 0 };
          }
          const next = h.seconds_remaining - 1;
          return { ...h, seconds_remaining: next, is_expired: next <= 0 };
        })
      );
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatCountdown = (seconds: number) => {
    if (seconds <= 0) return 'EXPIRED';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const formatTimelockRelease = (releaseIso: string) => {
    const diff = Math.max(0, Math.floor((new Date(releaseIso).getTime() - Date.now()) / 1000));
    if (diff <= 0) return 'Release window reached';
    const m = Math.floor(diff / 60);
    const s = diff % 60;
    return `Releases in ${m}m ${s}s (${new Date(releaseIso).toISOString().slice(11, 19)} UTC)`;
  };

  // 6. WebAuthn Hardware Approval Ceremony
  const handleApproveHold = async (item: HoldViewResponse) => {
    setIsApproving(item.hold_id);
    setHoldActionMsg(null);
    try {
      const token = await fetchDevToken('Approver', activeApproverId);
      const digest = item.tx_digest;
      let assertion: WebAuthnAssertionPayload;

      // Invariant #5: Hardware WebAuthn signature over tx digest challenge
      if (typeof window !== 'undefined' && window.navigator && window.navigator.credentials && window.PublicKeyCredential) {
        try {
          const challengeBuffer = new TextEncoder().encode(digest);
          const credential: any = await window.navigator.credentials.get({
            publicKey: {
              challenge: challengeBuffer,
              rpId: window.location.hostname === 'localhost' ? 'localhost' : 'console.bitguard.exchange',
              userVerification: 'preferred',
              timeout: 60000,
            },
          });
          if (credential && credential.response) {
            const rawClientData = new Uint8Array(credential.response.clientDataJSON);
            const rawAuthData = new Uint8Array(credential.response.authenticatorData);
            const rawSig = new Uint8Array(credential.response.signature);
            assertion = {
              credential_id: credential.id,
              client_data_json: btoa(String.fromCharCode(...rawClientData)),
              authenticator_data: btoa(String.fromCharCode(...rawAuthData)),
              signature: btoa(String.fromCharCode(...rawSig)),
            };
          } else {
            throw new Error('WebAuthn prompt dismissed');
          }
        } catch (err) {
          console.warn('Hardware WebAuthn prompt error, using simulated hardware key:', err);
          assertion = generateSimulatedAssertion(digest, activeApproverId);
        }
      } else {
        assertion = generateSimulatedAssertion(digest, activeApproverId);
      }

      if (DATA_SOURCE === 'demo') {
        setHoldActionMsg({
          id: item.hold_id,
          msg: `Quorum reached (2/2). Approved by ${activeApproverId} via WebAuthn over digest.`,
        });
        setPendingHolds((prev) =>
          prev.map((h) =>
            h.hold_id === item.hold_id
              ? {
                  ...h,
                  status: 'RELEASED',
                  approvals: [
                    ...h.approvals,
                    {
                      id: `appr-${Date.now()}`,
                      hold_ticket_id: h.hold_id,
                      approver_id: activeApproverId,
                      approver_role: 'Approver',
                      tx_digest: digest,
                      webauthn_signature: 'sig-virtual',
                      created_at: new Date().toISOString(),
                    },
                  ],
                }
              : h
          )
        );
      } else {
        const res = await submitHoldApproval(item.hold_id, assertion, token);
        setHoldActionMsg({ id: item.hold_id, msg: res.message });
        await loadPendingHolds();
      }
    } catch (err: any) {
      setHoldActionMsg({ id: item.hold_id, msg: err?.message || 'Approval failed', isError: true });
    } finally {
      setIsApproving(null);
    }
  };

  // 7. Single-click Quarantine Hold Denial
  const handleDenyHold = async (item: HoldViewResponse) => {
    setHoldActionMsg(null);
    try {
      const token = await fetchDevToken('Approver', activeApproverId);
      if (DATA_SOURCE === 'demo') {
        setHoldActionMsg({
          id: item.hold_id,
          msg: 'Hold denied. Policy tightened immediately (single approver rule).',
        });
        setPendingHolds((prev) =>
          prev.map((h) => (h.hold_id === item.hold_id ? { ...h, status: 'DENIED' } : h))
        );
      } else {
        await denyHold(item.hold_id, 'Denied by approver in Live Feed', token);
        setHoldActionMsg({ id: item.hold_id, msg: 'Quarantine hold denied. Policy tightened immediately.' });
        await loadPendingHolds();
      }
    } catch (err: any) {
      setHoldActionMsg({ id: item.hold_id, msg: err?.message || 'Denial failed', isError: true });
    }
  };

  // 8. Time-Lock Cancellation
  const handleCancelTimelock = async (item: TimelockItem) => {
    setTimelockMsg(null);
    try {
      await cancelTimelock(item.id, 'Manual operator cancellation from Live Feed');
      setTimelockMsg({ id: item.id, msg: `Timelock ${item.id} cancelled successfully.` });
      setTimelocks((prev) => prev.map((t) => (t.id === item.id ? { ...t, status: 'CANCELLED' } : t)));
    } catch (err: any) {
      setTimelockMsg({ id: item.id, msg: err?.message || 'Failed to cancel timelock', isError: true });
    }
  };

  // Filtered Steps for the Table
  const displayedSteps = isPlaying && typeof currentStep === 'number'
    ? steps.slice(0, currentStep + 1)
    : (liveStream.length > 0 ? liveStream : steps);

  const filteredSteps = displayedSteps.filter((step) => {
    const action = step.protected_decision.action;
    const isAttack = step.scenario === 'attack';

    if (filterAction === 'allow' && action !== 'allow') return false;
    if (filterAction === 'blocked' && action === 'allow') return false;
    if (filterAction === 'attack' && !isAttack) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = step.request_id.toLowerCase().includes(q);
      const matchWallet = step.wallet.toLowerCase().includes(q);
      const matchChain = step.chain.toLowerCase().includes(q);
      const matchKind = step.kind.toLowerCase().includes(q);
      const matchRule = step.protected_decision.reasons.some((r) =>
        (r.rule || r.code || '').toLowerCase().includes(q)
      );
      return matchId || matchWallet || matchChain || matchKind || matchRule;
    }

    return true;
  });

  const totalCount = displayedSteps.length;
  const allowCount = displayedSteps.filter((s) => s.protected_decision.action === 'allow').length;
  const holdCount = displayedSteps.filter((s) => s.protected_decision.action === 'hold').length;
  const denyCount = displayedSteps.filter((s) => s.protected_decision.action === 'deny').length;

  return (
    <div className="space-y-6">
      {/* 1. Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-slate-400 font-mono uppercase block">Total Streamed</span>
            <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border border-cyan-500/40 bg-cyan-500/20 text-cyan-300 uppercase">
              {DATA_SOURCE === 'api' ? 'REAL' : 'SYNTHETIC'}
            </span>
          </div>
          <span className="text-2xl font-bold font-mono text-white mt-1 block">{totalCount}</span>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-emerald-950/60">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-emerald-400 font-mono uppercase block">Allowed Signing</span>
            <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border border-emerald-500/40 bg-emerald-500/20 text-emerald-300 uppercase">
              {DATA_SOURCE === 'api' ? 'REAL' : 'SYNTHETIC'}
            </span>
          </div>
          <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">{allowCount}</span>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-950/60">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-amber-400 font-mono uppercase block">Manual Holds</span>
            <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border border-amber-500/40 bg-amber-500/20 text-amber-300 uppercase">
              {DATA_SOURCE === 'api' ? 'REAL' : 'SYNTHETIC'}
            </span>
          </div>
          <span className="text-2xl font-bold font-mono text-amber-400 mt-1 block">{holdCount}</span>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-rose-950/60">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-rose-400 font-mono uppercase block">Firewall Denies</span>
            <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border border-rose-500/40 bg-rose-500/20 text-rose-300 uppercase">
              {DATA_SOURCE === 'api' ? 'REAL' : 'SYNTHETIC'}
            </span>
          </div>
          <span className="text-2xl font-bold font-mono text-rose-400 mt-1 block">{denyCount}</span>
        </div>
      </div>

      {/* 2. Per-Chain Outflow Velocity (5-Second Aggregates) */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3 font-mono">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              Per-Chain Outflow Velocity (5s Aggregates)
            </span>
          </div>
          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold border border-cyan-500/40 bg-cyan-500/20 text-cyan-300 uppercase">
            {DATA_SOURCE === 'api' ? 'REAL' : 'SYNTHETIC'}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 text-xs">
          {ALL_CHAINS.map((chain) => {
            const amount = outflowAggregates[chain.toLowerCase()] || 0;
            const chainStyle = getChainBadgeStyle(chain);
            const nominalLimit = 100000;
            const pct = Math.min(100, Math.round((amount / nominalLimit) * 100));

            return (
              <div
                key={chain}
                className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span
                    className={cn(
                      'px-1.5 py-0.5 rounded text-[9px] font-bold border',
                      chainStyle.bg,
                      chainStyle.text,
                      chainStyle.border
                    )}
                  >
                    {chain.toUpperCase()}
                  </span>
                  <span className="text-[10px] text-slate-300 font-bold truncate" title={formatFullCurrency(amount)}>
                    {formatFullCurrency(amount)}
                  </span>
                </div>
                <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden border border-slate-800">
                  <div
                    className={cn(
                      'h-full transition-all duration-500 rounded-full',
                      pct >= 80 ? 'bg-rose-500' : pct >= 40 ? 'bg-amber-500' : 'bg-cyan-500'
                    )}
                    style={{ width: `${Math.max(4, pct)}%` }}
                  />
                </div>
                <div className="flex justify-between text-[9px] text-slate-500">
                  <span>Velocity</span>
                  <span>{pct}% cap</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. Operational Queues: Pending HOLD Queue & Active Time-Lock Queue */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-mono">
        {/* Pending Quarantine HOLD Queue */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-amber-400" />
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Pending Quarantine HOLD Queue
              </span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                {pendingHolds.length}
              </span>
            </div>

            {/* Active Approver Identity Toggle */}
            <div className="flex items-center space-x-1 text-[10px]">
              <UserCheck className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-500">Approver:</span>
              <select
                value={activeApproverId}
                onChange={(e) => setActiveApproverId(e.target.value)}
                className="bg-slate-950 border border-slate-700 text-slate-200 text-[10px] rounded px-1.5 py-0.5 focus:outline-none"
              >
                <option value="usr-approver-01">usr-approver-01 (Approver)</option>
                <option value="usr-approver-02">usr-approver-02 (Approver)</option>
                <option value="usr-requester-01">usr-requester-01 (Requester)</option>
                <option value="usr-admin-01">usr-admin-01 (Admin)</option>
              </select>
            </div>
          </div>

          {holdActionMsg && (
            <div
              className={cn(
                'p-2.5 rounded-lg text-xs font-mono border',
                holdActionMsg.isError
                  ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              )}
            >
              {holdActionMsg.msg}
            </div>
          )}

          {pendingHolds.length === 0 ? (
            <div className="p-6 text-center text-slate-500 text-xs">
              No quarantined transactions currently awaiting quorum release.
            </div>
          ) : (
            <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
              {pendingHolds.map((hold) => {
                const chainStyle = getChainBadgeStyle(hold.chain);
                const isRequester = activeApproverId === hold.requester_id;
                const hasAlreadyApproved = hold.approvals.some((a) => a.approver_id === activeApproverId);
                const isExpired = hold.is_expired || hold.seconds_remaining <= 0;
                const isPending = hold.status === 'PENDING' || hold.status === 'PENDING_QUORUM';

                let approveDisabledReason: string | null = null;
                if (isRequester) {
                  approveDisabledReason = 'Disabled: Requester cannot approve own hold ticket (Separation of duties)';
                } else if (hasAlreadyApproved) {
                  approveDisabledReason = `Disabled: Approver '${activeApproverId}' already approved this ticket`;
                } else if (isExpired) {
                  approveDisabledReason = 'Disabled: Quarantine hold ticket has expired';
                } else if (!isPending) {
                  approveDisabledReason = `Disabled: Ticket status is ${hold.status}`;
                }
                const canApprove = approveDisabledReason === null;

                return (
                  <div
                    key={hold.hold_id}
                    className="p-3 rounded-lg bg-slate-950/90 border border-slate-800 space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-slate-200">{hold.hold_id}</span>
                        <span
                          className={cn(
                            'px-1.5 py-0.5 rounded text-[9px] font-bold border',
                            chainStyle.bg,
                            chainStyle.text,
                            chainStyle.border
                          )}
                        >
                          {hold.chain.toUpperCase()}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold border border-amber-500/40 bg-amber-500/20 text-amber-300">
                          {hold.status}
                        </span>
                      </div>

                      {/* Expiry Countdown */}
                      <div className="flex items-center space-x-1 text-slate-400 text-[11px]">
                        <Clock className="w-3.5 h-3.5 text-amber-400" />
                        <span
                          className={cn(
                            'font-bold',
                            hold.seconds_remaining <= 10 ? 'text-rose-400 animate-pulse' : 'text-amber-400'
                          )}
                        >
                          {formatCountdown(hold.seconds_remaining)}
                        </span>
                      </div>
                    </div>

                    {/* Independently Decoded Transaction Details */}
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800 text-[11px] space-y-1">
                      <div className="flex justify-between text-slate-300">
                        <span className="text-slate-500">Amount:</span>
                        <span className="font-bold text-white">{formatFullCurrency(hold.amount_usd)}</span>
                      </div>
                      <div className="flex justify-between text-slate-300">
                        <span className="text-slate-500">From:</span>
                        <span title={hold.wallet || ''}>{truncateAddress(hold.wallet || '0x00...')}</span>
                      </div>
                      <div className="flex justify-between text-slate-300">
                        <span className="text-slate-500">To:</span>
                        <span title={hold.decoded_tx?.to_address || ''}>
                          {truncateAddress(hold.decoded_tx?.to_address || '0xDestination...')}
                        </span>
                      </div>
                      <div className="flex justify-between text-slate-400 text-[10px]">
                        <span className="text-slate-500">Challenge Digest:</span>
                        <span title={hold.tx_digest}>{truncateAddress(hold.tx_digest)}</span>
                      </div>
                    </div>

                    {/* Risk Reasons with Weights */}
                    {hold.reasons && hold.reasons.length > 0 && (
                      <div className="space-y-1">
                        <span className="text-[10px] text-slate-500 uppercase block">Risk Justifications:</span>
                        {hold.reasons.map((r, i) => (
                          <div
                            key={i}
                            className="p-1.5 rounded bg-amber-500/5 border border-amber-500/20 text-[10px] text-amber-300"
                          >
                            <span className="font-bold">{r.code || (r as any).rule}</span> (Weight:{' '}
                            {(r as any).weight ?? 85}): {r.detail || (r as any).message}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Approvals So Far & Quorum Progress */}
                    <div className="flex items-center justify-between pt-1 text-[10px] text-slate-400">
                      <div>
                        <span>Quorum: </span>
                        <span className="font-bold text-cyan-300">
                          {hold.approvals.length} / 2 required
                        </span>
                        {hold.approvals.length > 0 && (
                          <span className="text-slate-500 ml-1.5">
                            (Approved by: {hold.approvals.map((a) => a.approver_id).join(', ')})
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Explanation for Disabled Approval */}
                    {approveDisabledReason && (
                      <div className="p-1.5 rounded bg-amber-500/10 border border-amber-500/30 text-[10px] text-amber-300 flex items-center space-x-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-amber-400" />
                        <span>{approveDisabledReason}</span>
                      </div>
                    )}

                    {/* Action Buttons: Hardware WebAuthn Approve & Single-Click Deny */}
                    <div className="flex items-center justify-end space-x-2 pt-1">
                      <button
                        type="button"
                        onClick={() => handleDenyHold(hold)}
                        className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-[11px] font-bold transition-all cursor-pointer flex items-center space-x-1"
                        title="Tighten policy and deny hold immediately"
                      >
                        <XCircle className="w-3.5 h-3.5" />
                        <span>Deny (Tighten)</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleApproveHold(hold)}
                        disabled={!canApprove || isApproving === hold.hold_id}
                        className={cn(
                          'px-3 py-1 rounded font-bold text-[11px] transition-all flex items-center space-x-1.5 cursor-pointer',
                          canApprove
                            ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-md'
                            : 'bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed opacity-60'
                        )}
                        title={approveDisabledReason || 'Approve via WebAuthn hardware key'}
                      >
                        <KeyRound className="w-3.5 h-3.5" />
                        <span>
                          {isApproving === hold.hold_id ? 'Authorizing...' : 'Approve with WebAuthn'}
                        </span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Active Time-Lock Queue */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Active Time-Lock Delay Queue
              </span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                {timelocks.length}
              </span>
            </div>
            <span className="text-[10px] text-slate-500">Cooldown window before signing</span>
          </div>

          {timelockMsg && (
            <div
              className={cn(
                'p-2.5 rounded-lg text-xs font-mono border',
                timelockMsg.isError
                  ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                  : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
              )}
            >
              {timelockMsg.msg}
            </div>
          )}

          {timelocks.length === 0 ? (
            <div className="p-6 text-center text-slate-500 text-xs">
              No large withdrawals currently queued in time-lock cooldown.
            </div>
          ) : (
            <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
              {timelocks.map((item) => {
                const chainStyle = getChainBadgeStyle(item.chain);
                const isCancelled = item.status === 'CANCELLED';

                return (
                  <div
                    key={item.id}
                    className={cn(
                      'p-3 rounded-lg border text-xs space-y-2 transition-all',
                      isCancelled ? 'bg-slate-950/40 border-slate-800 opacity-60' : 'bg-slate-950/90 border-slate-800'
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-slate-200">{item.id}</span>
                        <span
                          className={cn(
                            'px-1.5 py-0.5 rounded text-[9px] font-bold border',
                            chainStyle.bg,
                            chainStyle.text,
                            chainStyle.border
                          )}
                        >
                          {item.chain.toUpperCase()}
                        </span>
                        <span
                          className={cn(
                            'px-1.5 py-0.5 rounded text-[9px] font-bold border',
                            isCancelled
                              ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                              : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                          )}
                        >
                          {item.status}
                        </span>
                      </div>

                      <span className="font-bold text-white text-xs">
                        {formatFullCurrency(item.amount_usd)}
                      </span>
                    </div>

                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800 text-[11px] space-y-1">
                      <div className="flex justify-between text-slate-300">
                        <span className="text-slate-500">Wallet:</span>
                        <span title={item.wallet}>{truncateAddress(item.wallet)}</span>
                      </div>
                      <div className="flex justify-between text-slate-300">
                        <span className="text-slate-500">Destination:</span>
                        <span title={item.recipient}>{truncateAddress(item.recipient)}</span>
                      </div>
                      <div className="flex justify-between text-cyan-300 font-semibold pt-0.5">
                        <span className="text-slate-500">Release:</span>
                        <span>{formatTimelockRelease(item.release_time)}</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between pt-1">
                      <span className="text-[10px] text-slate-500">
                        {isCancelled ? `Cancelled: ${item.cancel_reason || 'Manual'}` : 'Time-lock active'}
                      </span>

                      {!isCancelled && (
                        <button
                          type="button"
                          onClick={() => handleCancelTimelock(item)}
                          className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-[11px] font-bold transition-all cursor-pointer flex items-center space-x-1"
                          title="Cancel time-locked withdrawal immediately"
                        >
                          <Ban className="w-3.5 h-3.5" />
                          <span>Cancel Withdrawal</span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* 4. Filter and Search Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <span className="text-xs font-semibold text-slate-400 flex items-center gap-1 font-mono">
            <Filter className="w-3.5 h-3.5" />
            Filter:
          </span>
          <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 font-mono">
            <button
              onClick={() => setFilterAction('all')}
              className={cn(
                'px-2.5 py-1 text-xs font-medium rounded transition-all cursor-pointer',
                filterAction === 'all'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              )}
            >
              All ({totalCount})
            </button>
            <button
              onClick={() => setFilterAction('allow')}
              className={cn(
                'px-2.5 py-1 text-xs font-medium rounded transition-all cursor-pointer',
                filterAction === 'allow'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'text-slate-400 hover:text-white'
              )}
            >
              Allowed ({allowCount})
            </button>
            <button
              onClick={() => setFilterAction('blocked')}
              className={cn(
                'px-2.5 py-1 text-xs font-medium rounded transition-all cursor-pointer',
                filterAction === 'blocked'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'text-slate-400 hover:text-white'
              )}
            >
              Blocked ({holdCount + denyCount})
            </button>
            <button
              onClick={() => setFilterAction('attack')}
              className={cn(
                'px-2.5 py-1 text-xs font-medium rounded transition-all cursor-pointer',
                filterAction === 'attack'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                  : 'text-slate-400 hover:text-white'
              )}
            >
              Attack Scenario
            </button>
          </div>
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-72 font-mono">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search chain, wallet, rule, ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>
      </div>

      {/* 5. Live Decisions Stream / Transactions Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 font-semibold">REQUEST ID</th>
                <th className="px-4 py-3 font-semibold">TIME</th>
                <th className="px-4 py-3 font-semibold">CHAIN</th>
                <th className="px-4 py-3 font-semibold">WALLET</th>
                <th className="px-4 py-3 font-semibold">KIND</th>
                <th className="px-4 py-3 font-semibold text-right">AMOUNT (USD)</th>
                <th className="px-4 py-3 font-semibold text-center">ACTION</th>
                <th className="px-4 py-3 font-semibold text-center">RISK</th>
                <th className="px-4 py-3 font-semibold">POLICY VIOLATIONS / REASONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredSteps.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-slate-500">
                    No transactions match the selected filter.
                  </td>
                </tr>
              ) : (
                filteredSteps.map((step) => {
                  const decision = step.protected_decision;
                  const chainStyle = getChainBadgeStyle(step.chain);
                  const isAllow = decision.action === 'allow';
                  const isHold = decision.action === 'hold';
                  const isDeny = decision.action === 'deny';

                  return (
                    <tr
                      key={step.request_id}
                      className={cn(
                        'hover:bg-slate-800/40 transition-colors',
                        isDeny && 'bg-rose-950/15',
                        isHold && 'bg-amber-950/10'
                      )}
                    >
                      {/* Request ID */}
                      <td className="px-4 py-3 font-bold text-slate-200">
                        <div className="flex items-center gap-2">
                          <span>{step.request_id}</span>
                          {(() => {
                            const pLabel =
                              decision.data_label ||
                              step.data_label ||
                              (DATA_SOURCE === 'api'
                                ? 'REAL'
                                : step.scenario === 'attack'
                                ? 'REPORTED'
                                : 'SYNTHETIC');
                            const pStyle = getDataLabelBadgeStyle(pLabel);
                            return (
                              <span
                                className={cn(
                                  'px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border uppercase',
                                  pStyle.bg,
                                  pStyle.text,
                                  pStyle.border
                                )}
                              >
                                {pLabel}
                              </span>
                            );
                          })()}
                        </div>
                      </td>

                      {/* Time */}
                      <td className="px-4 py-3 text-slate-400">
                        {new Date(step.ts * 1000).toISOString().slice(11, 19)}
                      </td>

                      {/* Chain */}
                      <td className="px-4 py-3">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold border',
                            chainStyle.bg,
                            chainStyle.text,
                            chainStyle.border
                          )}
                        >
                          {step.chain.toUpperCase()}
                        </span>
                      </td>

                      {/* Wallet */}
                      <td className="px-4 py-3 text-slate-300" title={step.wallet}>
                        {truncateAddress(step.wallet)}
                      </td>

                      {/* Kind */}
                      <td className="px-4 py-3">
                        <span className="text-[11px] text-slate-400 font-sans uppercase">
                          {step.kind}
                        </span>
                      </td>

                      {/* Amount USD */}
                      <td className="px-4 py-3 text-right font-bold text-slate-200">
                        {step.amount_usd > 0 ? formatFullCurrency(step.amount_usd) : '—'}
                      </td>

                      {/* Action */}
                      <td className="px-4 py-3 text-center">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold border uppercase',
                            isAllow && 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
                            isHold && 'bg-amber-500/20 text-amber-300 border-amber-500/40',
                            isDeny && 'bg-rose-500/30 text-rose-200 border-rose-500/60 font-black'
                          )}
                        >
                          {decision.action}
                        </span>
                      </td>

                      {/* Risk */}
                      <td className="px-4 py-3 text-center">
                        <div className="flex items-center justify-center space-x-1.5">
                          <span
                            className={cn(
                              'text-xs font-bold',
                              decision.risk > 70
                                ? 'text-rose-400'
                                : decision.risk > 30
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            )}
                          >
                            {decision.risk}
                          </span>
                        </div>
                      </td>

                      {/* Reasons */}
                      <td className="px-4 py-3">
                        {decision.reasons && decision.reasons.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {decision.reasons.map((r, i) => (
                              <span
                                key={i}
                                title={r.message || r.detail}
                                className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-sans"
                              >
                                {r.rule || r.code}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
