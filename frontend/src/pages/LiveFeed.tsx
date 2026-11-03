import React, { useState, useEffect } from 'react';
import { StepEvent, DATA_SOURCE } from '../api';
import { formatFullCurrency, getChainBadgeStyle, getDataLabelBadgeStyle, truncateAddress, cn } from '../utils';
import { Search, Filter } from 'lucide-react';

interface LiveFeedProps {
  steps: StepEvent[];
  currentStep?: number;
  isPlaying?: boolean;
}

const SAMPLE_CHAINS = ['ethereum', 'bitcoin', 'solana', 'tron', 'arbitrum', 'base', 'optimism'];
const SAMPLE_WALLETS = [
  '0xBinanceHotETH1',
  'bc1qBinanceHotBTC1',
  'SolBinanceHot1',
  'TBinanceHotTRX1',
  '0xBinanceHotArb1',
  '0xBinanceHotBase1',
];

export const LiveFeed: React.FC<LiveFeedProps> = ({ steps, currentStep, isPlaying }) => {
  const [filterAction, setFilterAction] = useState<'all' | 'allow' | 'blocked' | 'attack'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [liveStream, setLiveStream] = useState<StepEvent[]>([]);

  // Synchronize initial or replay stream
  useEffect(() => {
    if (isPlaying && typeof currentStep === 'number') {
      setLiveStream(steps.slice(0, currentStep + 1));
    } else if (liveStream.length === 0 && steps.length > 0) {
      setLiveStream(steps);
    }
  }, [steps, currentStep, isPlaying]);

  // When idle, run a simulated background interval (every 3 seconds)
  // that adds a realistic micro-withdrawal (ALLOW, 0 Risk) to the top of the feed
  useEffect(() => {
    if (isPlaying) return;

    const interval = setInterval(() => {
      const randomIdx = Math.floor(Math.random() * SAMPLE_CHAINS.length);
      const chain = SAMPLE_CHAINS[randomIdx];
      const wallet = SAMPLE_WALLETS[randomIdx % SAMPLE_WALLETS.length];
      const txId = `tx-live-${Math.random().toString(36).substring(2, 8)}`;
      const amount = Math.floor(Math.random() * 4500) + 120; // $120 - $4,620

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
        },
        cumulative_unprotected_loss_usd: 0,
        cumulative_protected_loss_usd: 0,
      };

      setLiveStream((prev) => [microWithdrawal, ...prev.slice(0, 99)]);
    }, 3000);

    return () => clearInterval(interval);
  }, [isPlaying]);

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
        r.rule.toLowerCase().includes(q)
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
      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <span className="text-xs text-slate-400 font-mono uppercase block">Total Streamed</span>
          <span className="text-2xl font-bold font-mono text-white mt-1 block">{totalCount}</span>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-emerald-950/60">
          <span className="text-xs text-emerald-400 font-mono uppercase block">Allowed Signing</span>
          <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">{allowCount}</span>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-950/60">
          <span className="text-xs text-amber-400 font-mono uppercase block">Manual Holds</span>
          <span className="text-2xl font-bold font-mono text-amber-400 mt-1 block">{holdCount}</span>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-rose-950/60">
          <span className="text-xs text-rose-400 font-mono uppercase block">Firewall Denies</span>
          <span className="text-2xl font-bold font-mono text-rose-400 mt-1 block">{denyCount}</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <span className="text-xs font-semibold text-slate-400 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" />
            Filter:
          </span>
          <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setFilterAction('all')}
              className={cn(
                'px-2.5 py-1 text-xs font-medium rounded transition-all',
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
                'px-2.5 py-1 text-xs font-medium rounded transition-all',
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
                'px-2.5 py-1 text-xs font-medium rounded transition-all',
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
                'px-2.5 py-1 text-xs font-medium rounded transition-all',
                filterAction === 'attack'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                  : 'text-slate-400 hover:text-white'
              )}
            >
              Attack Scenario
            </button>
          </div>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-72">
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

      {/* Transactions Table */}
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
                                title={r.message}
                                className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-sans"
                              >
                                {r.rule}
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
