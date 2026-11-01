import React from 'react';
import { Sliders, Zap, CheckCircle2 } from 'lucide-react';
import { PolicyOverrides } from '../api';
import { formatFullCurrency } from '../utils';

interface PolicySlidersProps {
  overrides: PolicyOverrides;
  onChangeOverrides: (overrides: PolicyOverrides) => void;
  onApply: () => void;
  isLoading?: boolean;
}

export const PolicySliders: React.FC<PolicySlidersProps> = ({
  overrides,
  onChangeOverrides,
  onApply,
  isLoading,
}) => {
  const singleTx = overrides.single_tx_usd ?? 50_000;
  const walletLimit = overrides.wallet_limit_usd ?? 100_000;
  const globalLimit = overrides.global_limit_usd ?? 500_000;
  const newRecipient = overrides.new_recipient_usd ?? 10_000;
  const sprayThreshold = overrides.spray_threshold ?? 50;

  const handlePreset = (preset: 'strict' | 'default' | 'permissive') => {
    switch (preset) {
      case 'strict':
        onChangeOverrides({
          single_tx_usd: 15_000,
          wallet_limit_usd: 35_000,
          global_limit_usd: 100_000,
          new_recipient_usd: 5_000,
          spray_threshold: 20,
        });
        break;
      case 'default':
        onChangeOverrides({
          single_tx_usd: 50_000,
          wallet_limit_usd: 100_000,
          global_limit_usd: 500_000,
          new_recipient_usd: 10_000,
          spray_threshold: 50,
        });
        break;
      case 'permissive':
        onChangeOverrides({
          single_tx_usd: 500_000,
          wallet_limit_usd: 1_000_000,
          global_limit_usd: 5_000_000,
          new_recipient_usd: 100_000,
          spray_threshold: 100,
        });
        break;
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-cyan-500/10 rounded-lg border border-cyan-500/20 text-cyan-400">
            <Sliders className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              Policy Sensitivity Simulator
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/50 text-cyan-300 font-mono">
                Live Engine Tuning
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Adjust exchange risk thresholds to evaluate sensitivity tradeoffs: loss mitigation vs. operational friction.
            </p>
          </div>
        </div>

        {/* Preset Buttons */}
        <div className="flex items-center space-x-2">
          <button
            onClick={() => handlePreset('strict')}
            className="px-2.5 py-1 text-xs font-semibold rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 hover:bg-rose-500/20 transition-all"
          >
            Strict Defense
          </button>
          <button
            onClick={() => handlePreset('default')}
            className="px-2.5 py-1 text-xs font-semibold rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20 transition-all"
          >
            Default Balance
          </button>
          <button
            onClick={() => handlePreset('permissive')}
            className="px-2.5 py-1 text-xs font-semibold rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 hover:bg-amber-500/20 transition-all"
          >
            Permissive
          </button>
        </div>
      </div>

      {/* Sliders Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 my-6">
        {/* Single TX Limit */}
        <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <span>Single TX Limit</span>
              <span className="text-[10px] text-slate-500 font-normal">(single_tx_usd)</span>
            </label>
            <span className="text-xs font-mono font-bold text-cyan-400">
              {formatFullCurrency(singleTx)}
            </span>
          </div>
          <input
            type="range"
            min={5_000}
            max={2_000_000}
            step={5_000}
            value={singleTx}
            onChange={(e) =>
              onChangeOverrides({ ...overrides, single_tx_usd: Number(e.target.value) })
            }
            className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
          />
          <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
            <span>$5k</span>
            <span>$50k (Def)</span>
            <span>$2M</span>
          </div>
        </div>

        {/* Wallet-level Rolling Limit */}
        <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <span>Wallet Velocity Limit</span>
              <span className="text-[10px] text-slate-500 font-normal">(1h window)</span>
            </label>
            <span className="text-xs font-mono font-bold text-cyan-400">
              {formatFullCurrency(walletLimit)}
            </span>
          </div>
          <input
            type="range"
            min={20_000}
            max={5_000_000}
            step={10_000}
            value={walletLimit}
            onChange={(e) =>
              onChangeOverrides({ ...overrides, wallet_limit_usd: Number(e.target.value) })
            }
            className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
          />
          <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
            <span>$20k</span>
            <span>$100k (Def)</span>
            <span>$5M</span>
          </div>
        </div>

        {/* Global Multi-Chain Limit */}
        <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <span>Global Multi-Chain Cap</span>
              <span className="text-[10px] text-slate-500 font-normal">(global_limit_usd)</span>
            </label>
            <span className="text-xs font-mono font-bold text-cyan-400">
              {formatFullCurrency(globalLimit)}
            </span>
          </div>
          <input
            type="range"
            min={50_000}
            max={20_000_000}
            step={50_000}
            value={globalLimit}
            onChange={(e) =>
              onChangeOverrides({ ...overrides, global_limit_usd: Number(e.target.value) })
            }
            className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
          />
          <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
            <span>$50k</span>
            <span>$500k (Def)</span>
            <span>$20M</span>
          </div>
        </div>

        {/* New Recipient Threshold */}
        <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <span>Unseen Recipient Limit</span>
              <span className="text-[10px] text-slate-500 font-normal">(new_recipient_usd)</span>
            </label>
            <span className="text-xs font-mono font-bold text-cyan-400">
              {formatFullCurrency(newRecipient)}
            </span>
          </div>
          <input
            type="range"
            min={1_000}
            max={200_000}
            step={1_000}
            value={newRecipient}
            onChange={(e) =>
              onChangeOverrides({ ...overrides, new_recipient_usd: Number(e.target.value) })
            }
            className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
          />
          <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
            <span>$1k</span>
            <span>$10k (Def)</span>
            <span>$200k</span>
          </div>
        </div>

        {/* 7702 Nonce Spray Threshold */}
        <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <span>Nonce Spray Detection</span>
              <span className="text-[10px] text-slate-500 font-normal">(consecutive count)</span>
            </label>
            <span className="text-xs font-mono font-bold text-cyan-400">
              {sprayThreshold} consecutive nonces
            </span>
          </div>
          <input
            type="range"
            min={10}
            max={100}
            step={5}
            value={sprayThreshold}
            onChange={(e) =>
              onChangeOverrides({ ...overrides, spray_threshold: Number(e.target.value) })
            }
            className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
          />
          <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
            <span>10</span>
            <span>50 (Def)</span>
            <span>100</span>
          </div>
        </div>

        {/* Action Panel */}
        <div className="p-4 rounded-lg bg-gradient-to-br from-cyan-950/30 to-blue-950/40 border border-cyan-500/20 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-cyan-300 text-xs font-bold mb-1">
              <Zap className="w-4 h-4 text-cyan-400" />
              <span>Sensitivity Analysis</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Re-executes both pipelines against the synthetic dataset with these parameters.
            </p>
          </div>
          <button
            onClick={onApply}
            disabled={isLoading}
            className="mt-3 w-full py-2 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {isLoading ? (
              <span>Running Simulation...</span>
            ) : (
              <>
                <CheckCircle2 className="w-4 h-4" />
                <span>Apply & Re-Simulate</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
