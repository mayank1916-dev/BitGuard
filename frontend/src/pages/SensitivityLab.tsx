import React, { useState, useEffect, useRef } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  Line,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import {
  Sliders,
  TrendingUp,
  CheckCircle2,
  RefreshCw,
  AlertCircle,
  Sparkles,
} from 'lucide-react';
import { fetchSensitivityMatrix } from '../api';
import { formatCurrency, formatFullCurrency, cn } from '../utils';

export interface BaseLimitsPayload {
  base_single_tx_usd: number;
  base_wallet_limit_usd: number;
  base_global_limit_usd: number;
  base_new_recipient_usd: number;
}

export const SensitivityLab: React.FC = () => {
  // 1. Slider inputs stored in active numeric state
  const [singleTx, setSingleTx] = useState<number>(50_000);
  const [walletLimit, setWalletLimit] = useState<number>(100_000);
  const [globalLimit, setGlobalLimit] = useState<number>(500_000);
  const [unseenLimit, setUnseenLimit] = useState<number>(10_000);

  // 2. Active state hook for normalized sensitivity results
  const [sensitivityResults, setSensitivityResults] = useState<any[]>([]);
  const [isRecalculating, setIsRecalculating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const debounceTimerRef = useRef<NodeJS.Timeout | null>(null);
  const latestReqIdRef = useRef<number>(0);

  // Execute recalculation against backend & normalize response keys
  const executeCalculation = async (
    currentSingleTx: number,
    currentWalletLimit: number,
    currentGlobalLimit: number,
    currentUnseenLimit: number
  ) => {
    const reqId = ++latestReqIdRef.current;
    setIsRecalculating(true);
    setError(null);

    try {
      const res: any = await fetchSensitivityMatrix({
        base_single_tx_usd: currentSingleTx,
        base_wallet_limit_usd: currentWalletLimit,
        base_global_limit_usd: currentGlobalLimit,
        base_new_recipient_usd: currentUnseenLimit,
        multipliers: [0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0],
      });

      // Normalize response so property names strictly match what Recharts and the table expect
      const rawList = Array.isArray(res)
        ? res
        : Array.isArray(res?.data)
        ? res.data
        : (res?.tiers || res?.matrix || res?.data?.tiers || res?.data?.matrix || []);

      const normalized = rawList.map((tier: any) => ({
        multiplier:
          typeof tier.multiplier === 'number'
            ? `${tier.multiplier}x`
            : typeof tier.limit_multiplier === 'number'
            ? `${tier.limit_multiplier}x`
            : String(tier.multiplier ?? tier.limit_multiplier ?? '1x'),
        capitalSaved: Number(tier.capital_saved_usd ?? tier.capitalSaved ?? tier.loss_prevented_usd ?? 0),
        falsePositives: Number(tier.false_positives ?? tier.falsePositives ?? tier.false_positives_count ?? tier.false_positives_held ?? 0),
        singleTxCap: Number(tier.effective_single_tx_cap ?? tier.singleTxCap ?? tier.single_tx_usd ?? 0),
        breakerState: String(tier.breaker_state ?? tier.breakerState ?? tier.breaker_final_state ?? 'NORMAL').toUpperCase(),
        raw: tier,
      }));

      // Ignore if a newer request was dispatched
      if (reqId === latestReqIdRef.current) {
        setSensitivityResults(normalized);
      }
    } catch (err: any) {
      if (reqId === latestReqIdRef.current) {
        console.error('Sensitivity matrix calculation error:', err);
        setError('Failed to recalculate sensitivity curve from backend.');
      }
    } finally {
      if (reqId === latestReqIdRef.current) {
        setIsRecalculating(false);
      }
    }
  };

  // 3. Debounced useEffect (150ms) listening to [singleTx, walletLimit, globalLimit, unseenLimit]
  useEffect(() => {
    setIsRecalculating(true);
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }

    debounceTimerRef.current = setTimeout(() => {
      executeCalculation(singleTx, walletLimit, globalLimit, unseenLimit);
    }, 150);

    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }
    };
  }, [singleTx, walletLimit, globalLimit, unseenLimit]);

  const handlePreset = (preset: 'strict' | 'default' | 'permissive' | 'relaxed') => {
    switch (preset) {
      case 'strict':
        setSingleTx(15_000);
        setWalletLimit(35_000);
        setGlobalLimit(100_000);
        setUnseenLimit(5_000);
        break;
      case 'default':
        setSingleTx(50_000);
        setWalletLimit(100_000);
        setGlobalLimit(500_000);
        setUnseenLimit(10_000);
        break;
      case 'permissive':
        setSingleTx(500_000);
        setWalletLimit(1_000_000);
        setGlobalLimit(5_000_000);
        setUnseenLimit(100_000);
        break;
      case 'relaxed':
        setSingleTx(25_000_000);
        setWalletLimit(50_000_000);
        setGlobalLimit(100_000_000);
        setUnseenLimit(1_000_000);
        break;
    }
  };

  // Identify baseline (1.0x) stats
  const baselinePoint = sensitivityResults.find(
    (p) => p.multiplier === '1x' || p.multiplier === '1.0x' || p.multiplier === 1 || p.multiplier === 1.0
  );

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl backdrop-blur">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-3.5">
            <div className="p-2.5 bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 rounded-lg border border-cyan-500/30 text-cyan-400">
              <TrendingUp className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
                Policy Sensitivity Lab & Dynamic Frontier Curve
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/50 text-cyan-300 font-mono">
                  Live Dynamic Recalculation (150ms)
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Adjust any of the 4 sliders to dynamically evaluate the risk frontier: Capital Saved ($) vs. False Positives (Txs Held).
              </p>
            </div>
          </div>

          {/* Quick Presets */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => handlePreset('strict')}
              className="px-2.5 py-1 text-xs font-semibold rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 hover:bg-rose-500/20 transition-all cursor-pointer"
            >
              Strict Defense
            </button>
            <button
              onClick={() => handlePreset('default')}
              className="px-2.5 py-1 text-xs font-semibold rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20 transition-all cursor-pointer"
            >
              Default (50k)
            </button>
            <button
              onClick={() => handlePreset('permissive')}
              className="px-2.5 py-1 text-xs font-semibold rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 hover:bg-amber-500/20 transition-all cursor-pointer"
            >
              Permissive (500k)
            </button>
            <button
              onClick={() => handlePreset('relaxed')}
              className="px-2.5 py-1 text-xs font-semibold rounded bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 hover:bg-indigo-500/20 transition-all cursor-pointer"
            >
              Stress Test (25M)
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-center space-x-2 text-xs">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Frontier Chart Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        {/* Dynamic Updating Overlay / Badge */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div>
            <div className="flex items-center gap-2.5">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Exchange Risk Frontier: Capital Saved ($B) vs. False Positives (Txs Held)
              </h3>
              {isRecalculating ? (
                <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-500/50 text-[11px] font-mono text-cyan-300 animate-pulse">
                  <RefreshCw className="w-3 h-3 animate-spin" />
                  <span>Recalculating frontier...</span>
                </span>
              ) : (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-500/40 text-[10px] font-mono text-emerald-300">
                  <Sparkles className="w-3 h-3 text-emerald-400" />
                  <span>Dynamic Live Curve</span>
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Left Axis (Teal Area): Loss Prevented in $ Billions. Right Axis (Amber Line): Normal retail customer withdrawals held for review.
            </p>
          </div>

          <div className="flex items-center space-x-4 text-xs font-mono">
            <div className="flex items-center space-x-1.5">
              <span className="w-3 h-3 rounded-sm bg-cyan-500/30 border border-cyan-400" />
              <span className="text-slate-300">Capital Saved ($B)</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-3 h-0.5 bg-amber-400" />
              <span className="text-slate-300">False Positives (Held)</span>
            </div>
          </div>
        </div>

        {/* Recharts Container with dynamic key to force repaint on state update */}
        <div
          className={cn(
            'h-80 w-full mt-6 transition-opacity duration-200',
            isRecalculating ? 'opacity-70' : 'opacity-100'
          )}
        >
          <ResponsiveContainer
            key={`chart-render-${sensitivityResults.length}-${singleTx}-${walletLimit}-${globalLimit}-${unseenLimit}`}
            width="100%"
            height={320}
          >
            <ComposedChart data={sensitivityResults} margin={{ top: 10, right: 20, left: 10, bottom: 0 }}>
              <defs>
                <linearGradient id="capitalGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis
                dataKey="multiplier"
                stroke="#64748b"
                tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
              />
              {/* Y Axis Left: Capital Saved ($) */}
              <YAxis
                yAxisId="left"
                stroke="#06b6d4"
                tick={{ fill: '#06b6d4', fontSize: 11, fontFamily: 'monospace' }}
                tickFormatter={(v) => (v >= 1e9 ? `$${(v / 1e9).toFixed(1)}B` : v >= 1e6 ? `$${(v / 1e6).toFixed(0)}M` : `$${v}`)}
                domain={[0, 'auto']}
              />
              {/* Y Axis Right: False Positives */}
              <YAxis
                yAxisId="right"
                orientation="right"
                stroke="#f59e0b"
                tick={{ fill: '#f59e0b', fontSize: 11, fontFamily: 'monospace' }}
                domain={[0, 'auto']}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: '#334155',
                  borderRadius: '8px',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                  boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)',
                }}
                formatter={(value: any, name: any) => {
                  if (name === 'capitalSaved' || name === 'Capital Saved' || name === 'Capital Saved ($B)') {
                    const num = Number(value);
                    const inB = num >= 1e6 ? (num / 1e9).toFixed(2) : num.toFixed(2);
                    return [`$${inB} Billion`, 'Capital Saved'];
                  }
                  if (name === 'falsePositives' || name === 'False Positives' || name === 'False Positives (Held)') {
                    return [`${value} legitimate txs held`, 'False Positives'];
                  }
                  return [value, name];
                }}
              />
              <Area
                yAxisId="left"
                type="stepAfter"
                dataKey="capitalSaved"
                name="Capital Saved"
                stroke="#0891b2"
                fill="#06b6d4"
                fillOpacity={0.35}
                strokeWidth={2}
              />
              <Line
                yAxisId="right"
                type="stepAfter"
                dataKey="falsePositives"
                name="False Positives"
                stroke="#f59e0b"
                strokeWidth={3}
                dot={{ r: 4, fill: '#f59e0b' }}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Interactive Controls & Sensitivity Matrix Table */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Sliders for Base Limits */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 mb-4 border-b border-slate-800">
              <div className="flex items-center space-x-2 text-white font-bold text-sm">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span>Base Limit Tuning (1.0x Reference)</span>
              </div>
              {isRecalculating && (
                <RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
              )}
            </div>

            <div className="space-y-5">
              {/* Slider 1: Single TX USD */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">Single TX USD (single_tx_usd)</span>
                  <span className="text-cyan-400 font-mono font-bold">
                    {formatFullCurrency(singleTx)}
                  </span>
                </div>
                <input
                  type="range"
                  min={5_000}
                  max={30_000_000}
                  step={5_000}
                  value={singleTx}
                  onChange={(e) => setSingleTx(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                />
                <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
                  <span>$5k</span>
                  <span>$50k (Def)</span>
                  <span>$30M</span>
                </div>
              </div>

              {/* Slider 2: Wallet Limit USD */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">Wallet Velocity Limit (1h)</span>
                  <span className="text-cyan-400 font-mono font-bold">
                    {formatFullCurrency(walletLimit)}
                  </span>
                </div>
                <input
                  type="range"
                  min={20_000}
                  max={50_000_000}
                  step={10_000}
                  value={walletLimit}
                  onChange={(e) => setWalletLimit(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                />
                <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
                  <span>$20k</span>
                  <span>$100k (Def)</span>
                  <span>$50M</span>
                </div>
              </div>

              {/* Slider 3: Global Limit USD */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">Global Multi-Chain Cap</span>
                  <span className="text-cyan-400 font-mono font-bold">
                    {formatFullCurrency(globalLimit)}
                  </span>
                </div>
                <input
                  type="range"
                  min={50_000}
                  max={100_000_000}
                  step={50_000}
                  value={globalLimit}
                  onChange={(e) => setGlobalLimit(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                />
                <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
                  <span>$50k</span>
                  <span>$500k (Def)</span>
                  <span>$100M</span>
                </div>
              </div>

              {/* Slider 4: New Recipient USD */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">Unseen Recipient Limit</span>
                  <span className="text-cyan-400 font-mono font-bold">
                    {formatFullCurrency(unseenLimit)}
                  </span>
                </div>
                <input
                  type="range"
                  min={1_000}
                  max={200_000}
                  step={1_000}
                  value={unseenLimit}
                  onChange={(e) => setUnseenLimit(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                />
                <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
                  <span>$1k</span>
                  <span>$10k (Def)</span>
                  <span>$200k</span>
                </div>
              </div>
            </div>
          </div>

          {/* Current Baseline Status Callout */}
          <div className="mt-6 p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300">
            <div className="flex items-center space-x-1.5 font-bold mb-1">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Current 1.0x Baseline Status</span>
            </div>
            <p className="text-[11px] text-emerald-200/80 leading-relaxed">
              {baselinePoint ? (
                <>
                  Prevents <strong>{formatCurrency(baselinePoint.capitalSaved)} ({((baselinePoint.capitalSaved / 4.39e9) * 100).toFixed(1)}%)</strong> of exploit loss with <strong>{baselinePoint.falsePositives} false positive hold(s)</strong>.
                </>
              ) : (
                'Recalculating status...'
              )}
            </p>
          </div>
        </div>

        {/* Matrix Data Table */}
        <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
            <h4 className="text-xs font-bold font-mono uppercase text-slate-300">
              Sensitivity Evaluation Matrix
            </h4>
            <span className="text-[10px] font-mono text-slate-500">
              {sensitivityResults.length} Multiplier Tiers Evaluated
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-4 py-2.5 font-semibold">MULTIPLIER</th>
                  <th className="px-4 py-2.5 font-semibold">SINGLE TX CAP</th>
                  <th className="px-4 py-2.5 font-semibold">CAPITAL SAVED ($)</th>
                  <th className="px-4 py-2.5 font-semibold text-center">MITIGATED (%)</th>
                  <th className="px-4 py-2.5 font-semibold text-center">FALSE POSITIVES</th>
                  <th className="px-4 py-2.5 font-semibold">BREAKER STATE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {sensitivityResults.map((tier: any) => {
                  const isSweetSpot = tier.multiplier === '1x' || tier.multiplier === '1.0x' || tier.multiplier === 1 || tier.multiplier === 1.0;
                  return (
                    <tr
                      key={tier.multiplier}
                      className={cn(
                        'hover:bg-slate-800/40 transition-colors',
                        isSweetSpot && 'bg-cyan-500/10 font-bold'
                      )}
                    >
                      <td className="px-4 py-2.5 text-slate-200">
                        {tier.multiplier}
                        {isSweetSpot && (
                          <span className="ml-1.5 text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                            BASELINE
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-slate-300">
                        ${tier.singleTxCap.toLocaleString()}
                      </td>
                      <td className="px-4 py-2.5 font-bold text-emerald-400">
                        ${(tier.capitalSaved / 1e9).toFixed(2)}B
                      </td>
                      <td className="px-4 py-2.5 text-center text-emerald-300 font-bold">
                        {((tier.capitalSaved / 4.39e9) * 100).toFixed(1)}%
                      </td>
                      <td className="px-4 py-2.5 text-center">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold border',
                            tier.falsePositives === 0
                              ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                              : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          )}
                        >
                          {tier.falsePositives} txs
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold border uppercase',
                            tier.breakerState === 'LOCKDOWN'
                              ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                              : 'bg-slate-800 text-slate-300 border-slate-700'
                          )}
                        >
                          {tier.breakerState}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export const PolicyLabView = SensitivityLab;
export default SensitivityLab;
