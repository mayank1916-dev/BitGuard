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
import { fetchSensitivityMatrix, SensitivityPoint } from '../api';
import { formatCurrency, formatFullCurrency, cn } from '../utils';

export interface BaseLimitsPayload {
  base_single_tx_usd: number;
  base_wallet_limit_usd: number;
  base_global_limit_usd: number;
  base_new_recipient_usd: number;
}

export const SensitivityLab: React.FC = () => {
  // 1. All 4 sliders stored in active React state
  const [baseSingleTxUsd, setBaseSingleTxUsd] = useState<number>(50_000);
  const [baseWalletLimitUsd, setBaseWalletLimitUsd] = useState<number>(100_000);
  const [baseGlobalLimitUsd, setBaseGlobalLimitUsd] = useState<number>(500_000);
  const [baseNewRecipientUsd, setBaseNewRecipientUsd] = useState<number>(10_000);

  const [matrixData, setMatrixData] = useState<SensitivityPoint[]>([]);
  const [isRecalculating, setIsRecalculating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const debounceTimerRef = useRef<NodeJS.Timeout | null>(null);
  const latestReqIdRef = useRef<number>(0);

  // Execute recalculation against backend
  const executeCalculation = async (limits: BaseLimitsPayload) => {
    const reqId = ++latestReqIdRef.current;
    setIsRecalculating(true);
    setError(null);

    try {
      const res = await fetchSensitivityMatrix({
        base_single_tx_usd: limits.base_single_tx_usd,
        base_wallet_limit_usd: limits.base_wallet_limit_usd,
        base_global_limit_usd: limits.base_global_limit_usd,
        base_new_recipient_usd: limits.base_new_recipient_usd,
        multipliers: [0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0],
      });

      // Ignore if a newer request was dispatched
      if (reqId === latestReqIdRef.current) {
        setMatrixData(res.matrix);
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

  // 2. 150ms debounce on ANY of the 4 slider value changes
  useEffect(() => {
    setIsRecalculating(true);
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }

    debounceTimerRef.current = setTimeout(() => {
      executeCalculation({
        base_single_tx_usd: baseSingleTxUsd,
        base_wallet_limit_usd: baseWalletLimitUsd,
        base_global_limit_usd: baseGlobalLimitUsd,
        base_new_recipient_usd: baseNewRecipientUsd,
      });
    }, 150);

    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }
    };
  }, [baseSingleTxUsd, baseWalletLimitUsd, baseGlobalLimitUsd, baseNewRecipientUsd]);

  const handlePreset = (preset: 'strict' | 'default' | 'permissive' | 'relaxed') => {
    switch (preset) {
      case 'strict':
        setBaseSingleTxUsd(15_000);
        setBaseWalletLimitUsd(35_000);
        setBaseGlobalLimitUsd(100_000);
        setBaseNewRecipientUsd(5_000);
        break;
      case 'default':
        setBaseSingleTxUsd(50_000);
        setBaseWalletLimitUsd(100_000);
        setBaseGlobalLimitUsd(500_000);
        setBaseNewRecipientUsd(10_000);
        break;
      case 'permissive':
        setBaseSingleTxUsd(500_000);
        setBaseWalletLimitUsd(1_000_000);
        setBaseGlobalLimitUsd(5_000_000);
        setBaseNewRecipientUsd(100_000);
        break;
      case 'relaxed':
        setBaseSingleTxUsd(25_000_000);
        setBaseWalletLimitUsd(50_000_000);
        setBaseGlobalLimitUsd(100_000_000);
        setBaseNewRecipientUsd(1_000_000);
        break;
    }
  };

  // Recharts dataset with both capitalSaved and capitalSavedB, and falsePositives
  const chartData = matrixData.map((pt) => {
    const mult = pt.multiplier ?? pt.limit_multiplier;
    const capitalSavedUsd = pt.capital_saved_usd ?? pt.loss_prevented_usd;
    const falsePos = pt.false_positives_count ?? pt.false_positives_held;
    const singleTx = pt.effective_single_tx_cap ?? pt.single_tx_usd;
    const mitigated = pt.mitigated_pct ?? pt.loss_mitigated_pct;

    return {
      multiplier: `${mult}x`,
      capitalSaved: Number((capitalSavedUsd / 1e9).toFixed(3)),
      capitalSavedB: Number((capitalSavedUsd / 1e9).toFixed(3)),
      mitigatedPct: mitigated,
      falsePositives: falsePos,
      singleTxLimit: singleTx,
      walletLimit: pt.wallet_limit_usd,
      raw: pt,
    };
  });

  // Identify baseline (1.0x) stats
  const baselinePoint = matrixData.find(
    (p) => (p.multiplier ?? p.limit_multiplier) === 1.0
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

        {/* Recharts Container */}
        <div
          className={cn(
            'h-80 w-full mt-6 transition-opacity duration-200',
            isRecalculating ? 'opacity-70' : 'opacity-100'
          )}
        >
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={chartData} margin={{ top: 10, right: 20, left: 10, bottom: 0 }}>
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
              {/* Y Axis Left: Capital Saved ($B) */}
              <YAxis
                yAxisId="left"
                stroke="#06b6d4"
                tick={{ fill: '#06b6d4', fontSize: 11, fontFamily: 'monospace' }}
                unit="B"
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
                  if (name === 'Capital Saved ($B)' || name === 'Capital Saved') return [`$${value} Billion`, 'Capital Saved ($B)'];
                  if (name === 'False Positives (Held)' || name === 'False Positives') return [`${value} legitimate txs held`, 'False Positives (Held)'];
                  return [value, name];
                }}
              />
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="capitalSaved"
                name="Capital Saved ($B)"
                stroke="#06b6d4"
                fillOpacity={1}
                fill="url(#capitalGradient)"
                strokeWidth={2}
              />
              <Line
                yAxisId="right"
                type="stepAfter"
                dataKey="falsePositives"
                name="False Positives (Held)"
                stroke="#f59e0b"
                strokeWidth={2.5}
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
                    {formatFullCurrency(baseSingleTxUsd)}
                  </span>
                </div>
                <input
                  type="range"
                  min={5_000}
                  max={30_000_000}
                  step={5_000}
                  value={baseSingleTxUsd}
                  onChange={(e) => setBaseSingleTxUsd(Number(e.target.value))}
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
                    {formatFullCurrency(baseWalletLimitUsd)}
                  </span>
                </div>
                <input
                  type="range"
                  min={20_000}
                  max={50_000_000}
                  step={10_000}
                  value={baseWalletLimitUsd}
                  onChange={(e) => setBaseWalletLimitUsd(Number(e.target.value))}
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
                    {formatFullCurrency(baseGlobalLimitUsd)}
                  </span>
                </div>
                <input
                  type="range"
                  min={50_000}
                  max={100_000_000}
                  step={50_000}
                  value={baseGlobalLimitUsd}
                  onChange={(e) => setBaseGlobalLimitUsd(Number(e.target.value))}
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
                    {formatFullCurrency(baseNewRecipientUsd)}
                  </span>
                </div>
                <input
                  type="range"
                  min={1_000}
                  max={200_000}
                  step={1_000}
                  value={baseNewRecipientUsd}
                  onChange={(e) => setBaseNewRecipientUsd(Number(e.target.value))}
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
                  Prevents <strong>{formatCurrency(baselinePoint.capital_saved_usd ?? baselinePoint.loss_prevented_usd)} ({(baselinePoint.mitigated_pct ?? baselinePoint.loss_mitigated_pct).toFixed(1)}%)</strong> of exploit loss with <strong>{baselinePoint.false_positives_count ?? baselinePoint.false_positives_held} false positive hold(s)</strong>.
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
              {matrixData.length} Multiplier Tiers Evaluated
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
                {matrixData.map((row) => {
                  const mult = row.multiplier ?? row.limit_multiplier;
                  const isSweetSpot = mult === 1.0;
                  const singleTx = row.effective_single_tx_cap ?? row.single_tx_usd;
                  const saved = row.capital_saved_usd ?? row.loss_prevented_usd;
                  const mitigated = row.mitigated_pct ?? row.loss_mitigated_pct;
                  const falsePos = row.false_positives_count ?? row.false_positives_held;
                  const state = row.breaker_state ?? row.breaker_final_state;

                  return (
                    <tr
                      key={mult}
                      className={cn(
                        'hover:bg-slate-800/40 transition-colors',
                        isSweetSpot && 'bg-cyan-500/10 font-bold'
                      )}
                    >
                      <td className="px-4 py-2.5 text-slate-200">
                        {mult}x
                        {isSweetSpot && (
                          <span className="ml-1.5 text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                            BASELINE
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-slate-300">
                        {formatFullCurrency(singleTx)}
                      </td>
                      <td className="px-4 py-2.5 font-bold text-emerald-400">
                        {formatCurrency(saved)}
                      </td>
                      <td className="px-4 py-2.5 text-center text-emerald-300 font-bold">
                        {mitigated.toFixed(1)}%
                      </td>
                      <td className="px-4 py-2.5 text-center">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold border',
                            falsePos === 0
                              ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                              : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          )}
                        >
                          {falsePos} txs
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold border uppercase',
                            state === 'Lockdown'
                              ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                              : 'bg-slate-800 text-slate-300 border-slate-700'
                          )}
                        >
                          {state}
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
