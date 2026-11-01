import React, { useState, useEffect } from 'react';
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
} from 'lucide-react';
import { fetchSensitivityMatrix, SensitivityPoint, PolicyOverrides } from '../api';
import { formatCurrency, formatFullCurrency, cn } from '../utils';

export const PolicyLabView: React.FC = () => {
  const [baseLimits, setBaseLimits] = useState<PolicyOverrides>({
    single_tx_usd: 50_000,
    wallet_limit_usd: 100_000,
    global_limit_usd: 500_000,
    new_recipient_usd: 10_000,
  });

  const [matrixData, setMatrixData] = useState<SensitivityPoint[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const loadMatrix = async (limits?: PolicyOverrides) => {
    setIsLoading(true);
    setError(null);
    try {
      const activeLimits = limits ?? baseLimits;
      const res = await fetchSensitivityMatrix({
        base_limits: activeLimits,
        multipliers: [0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0],
      });
      setMatrixData(res.matrix);
    } catch (err: any) {
      console.error('Failed to load sensitivity matrix:', err);
      setError('Could not connect to backend sensitivity endpoint.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadMatrix();
  }, []);

  // Format data for Recharts
  const chartData = matrixData.map((pt) => ({
    multiplier: `${pt.limit_multiplier}x`,
    capitalSavedB: Number((pt.loss_prevented_usd / 1e9).toFixed(3)),
    mitigatedPct: pt.loss_mitigated_pct,
    falsePositives: pt.false_positives_held,
    singleTxLimit: pt.single_tx_usd,
    walletLimit: pt.wallet_limit_usd,
    raw: pt,
  }));

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
                Policy Sensitivity Lab & Frontier Curve
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/50 text-cyan-300 font-mono">
                  Pareto Trade-off Analytics
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Quantify the tradeoff between capital protected during an exploit cascade versus operational friction from legitimate customer withdrawal holds.
              </p>
            </div>
          </div>

          <button
            onClick={() => loadMatrix()}
            disabled={isLoading}
            className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50 cursor-pointer self-start sm:self-auto"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isLoading && 'animate-spin')} />
            <span>{isLoading ? 'Recalculating...' : 'Refresh Curve'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-center space-x-2 text-xs">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Frontier Chart */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide">
              Exchange Risk Frontier: Capital Saved ($B) vs. False Positives (Txs Held)
            </h3>
            <p className="text-xs text-slate-400">
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
        <div className="h-80 w-full mt-6">
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
                  if (name === 'Capital Saved ($B)') return [`$${value} Billion`, name];
                  if (name === 'False Positives (Held)') return [`${value} legitimate txs held`, name];
                  return [value, name];
                }}
              />
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="capitalSavedB"
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
            <div className="flex items-center space-x-2 text-white font-bold text-sm mb-4 pb-2 border-b border-slate-800">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>Base Limit Tuning (1.0x Reference)</span>
            </div>

            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">Single TX USD</span>
                  <span className="text-cyan-400 font-mono font-bold">
                    {formatFullCurrency(baseLimits.single_tx_usd ?? 50000)}
                  </span>
                </div>
                <input
                  type="range"
                  min={10000}
                  max={200000}
                  step={5000}
                  value={baseLimits.single_tx_usd ?? 50000}
                  onChange={(e) => {
                    const updated = { ...baseLimits, single_tx_usd: Number(e.target.value) };
                    setBaseLimits(updated);
                    loadMatrix(updated);
                  }}
                  className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">Wallet Limit USD</span>
                  <span className="text-cyan-400 font-mono font-bold">
                    {formatFullCurrency(baseLimits.wallet_limit_usd ?? 100000)}
                  </span>
                </div>
                <input
                  type="range"
                  min={25000}
                  max={500000}
                  step={10000}
                  value={baseLimits.wallet_limit_usd ?? 100000}
                  onChange={(e) => {
                    const updated = { ...baseLimits, wallet_limit_usd: Number(e.target.value) };
                    setBaseLimits(updated);
                    loadMatrix(updated);
                  }}
                  className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">Global Limit USD</span>
                  <span className="text-cyan-400 font-mono font-bold">
                    {formatFullCurrency(baseLimits.global_limit_usd ?? 500000)}
                  </span>
                </div>
                <input
                  type="range"
                  min={100000}
                  max={2000000}
                  step={50000}
                  value={baseLimits.global_limit_usd ?? 500000}
                  onChange={(e) => {
                    const updated = { ...baseLimits, global_limit_usd: Number(e.target.value) };
                    setBaseLimits(updated);
                    loadMatrix(updated);
                  }}
                  className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                />
              </div>
            </div>
          </div>

          {/* Sweet Spot Callout */}
          <div className="mt-6 p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300">
            <div className="flex items-center space-x-1.5 font-bold mb-1">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Recommended Sweet Spot (1.0x)</span>
            </div>
            <p className="text-[11px] text-emerald-200/80 leading-relaxed">
              At 1.0x multiplier, BitGuard mitigates <strong>100.0% of the $4.39B exploit</strong> while maintaining <strong>0 false positives</strong> across all legitimate customer withdrawals.
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
                  const isSweetSpot = row.limit_multiplier === 1.0;
                  return (
                    <tr
                      key={row.limit_multiplier}
                      className={cn(
                        'hover:bg-slate-800/40 transition-colors',
                        isSweetSpot && 'bg-cyan-500/10 font-bold'
                      )}
                    >
                      <td className="px-4 py-2.5 text-slate-200">
                        {row.limit_multiplier}x
                        {isSweetSpot && (
                          <span className="ml-1.5 text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                            BASELINE
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-slate-300">
                        {formatFullCurrency(row.single_tx_usd)}
                      </td>
                      <td className="px-4 py-2.5 font-bold text-emerald-400">
                        {formatCurrency(row.loss_prevented_usd)}
                      </td>
                      <td className="px-4 py-2.5 text-center text-emerald-300 font-bold">
                        {row.loss_mitigated_pct.toFixed(1)}%
                      </td>
                      <td className="px-4 py-2.5 text-center">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold border',
                            row.false_positives_held === 0
                              ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                              : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          )}
                        >
                          {row.false_positives_held} txs
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold border uppercase',
                            row.breaker_final_state === 'Lockdown'
                              ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                              : 'bg-slate-800 text-slate-300 border-slate-700'
                          )}
                        >
                          {row.breaker_final_state}
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
