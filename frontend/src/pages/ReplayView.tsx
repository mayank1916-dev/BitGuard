import React, { useState, useEffect, useRef } from 'react';
import {
  Play,
  Pause,
  RotateCcw,
  ShieldCheck,
  AlertTriangle,
  Flame,
} from 'lucide-react';
import { StepEvent, ReplayMetrics } from '../api';
import { formatCurrency, formatFullCurrency, getChainBadgeStyle, truncateAddress, cn } from '../utils';

interface ReplayViewProps {
  steps: StepEvent[];
  summary?: ReplayMetrics | null;
  onRunSimulation?: () => void;
  isLoading?: boolean;
}

export const ReplayView: React.FC<ReplayViewProps> = ({ steps }) => {
  const [currentIndex, setCurrentIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1); // 1x, 5x, 10x

  const leftListRef = useRef<HTMLDivElement>(null);
  const rightListRef = useRef<HTMLDivElement>(null);

  // Playback timer loop
  useEffect(() => {
    if (!isPlaying || steps.length === 0) return;

    const intervalTime = Math.max(20, Math.floor(250 / playbackSpeed));
    const timer = setInterval(() => {
      setCurrentIndex((prev) => {
        if (prev >= steps.length - 1) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, intervalTime);

    return () => clearInterval(timer);
  }, [isPlaying, playbackSpeed, steps.length]);

  // Auto-scroll list as new steps appear
  useEffect(() => {
    if (leftListRef.current) {
      leftListRef.current.scrollTop = leftListRef.current.scrollHeight;
    }
    if (rightListRef.current) {
      rightListRef.current.scrollTop = rightListRef.current.scrollHeight;
    }
  }, [currentIndex]);

  const currentStep: StepEvent | undefined = steps[currentIndex];
  const visibleSteps = steps.slice(0, currentIndex + 1);

  // Ticking metrics at the current playback index
  const currentUnprotectedLoss = currentStep?.cumulative_unprotected_loss_usd ?? 0;
  const currentProtectedLoss = currentStep?.cumulative_protected_loss_usd ?? 0;
  const currentLossPrevented = Math.max(0, currentUnprotectedLoss - currentProtectedLoss);
  const currentPreventedPct =
    currentUnprotectedLoss > 0 ? (currentLossPrevented / currentUnprotectedLoss) * 100 : 100;

  // Identify tripwire event if one has fired by this step
  const tripwireStep = visibleSteps.find(
    (s) => s.protected_decision.action === 'hold' || s.protected_decision.action === 'deny'
  );

  const currentBreakerState = currentStep?.protected_decision.breaker_state || 'Normal';

  // Key Incident Markers for timeline scrubber
  const timelineMarkers = [
    { label: 'Baseline', index: 0, tag: 'T -600s' },
    { label: 'XRP Outflow ($120M)', index: 12, tag: 'T 0s' },
    { label: 'Multi-Chain Drain', index: 17, tag: 'T +35s' },
    { label: 'EIP-7702 Spray', index: 22, tag: 'T +110s' },
    { label: 'Massive Sweep ($2.18B)', index: 72, tag: 'T +180s' },
    { label: 'Secondary Pulls', index: 73, tag: 'T +35m' },
  ];

  const handleStart = () => {
    if (currentIndex >= steps.length - 1) {
      setCurrentIndex(0);
    }
    setIsPlaying(true);
  };

  const handlePause = () => {
    setIsPlaying(false);
  };

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentIndex(0);
  };

  const handleScrub = (e: React.ChangeEvent<HTMLInputElement>) => {
    setCurrentIndex(Number(e.target.value));
  };

  return (
    <div className="space-y-6">
      {/* Control Console */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-xl backdrop-blur">
        <div className="flex flex-wrap items-center justify-between gap-4">
          {/* Playback Buttons */}
          <div className="flex items-center space-x-3">
            {!isPlaying ? (
              <button
                onClick={handleStart}
                className="flex items-center space-x-2 px-5 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-sm shadow-md shadow-emerald-500/20 transition-all cursor-pointer"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Start Replay</span>
              </button>
            ) : (
              <button
                onClick={handlePause}
                className="flex items-center space-x-2 px-5 py-2.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-sm shadow-md shadow-amber-500/20 transition-all cursor-pointer"
              >
                <Pause className="w-4 h-4 fill-current" />
                <span>Pause</span>
              </button>
            )}

            <button
              onClick={handleReset}
              className="flex items-center space-x-1.5 px-3.5 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs transition-colors cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset</span>
            </button>

            {/* Speed Scrubbers */}
            <div className="flex items-center bg-slate-950 rounded-lg p-1 border border-slate-800">
              {[1, 5, 10].map((speed) => (
                <button
                  key={speed}
                  onClick={() => setPlaybackSpeed(speed)}
                  className={cn(
                    'px-2.5 py-1 text-xs font-mono font-bold rounded transition-all cursor-pointer',
                    playbackSpeed === speed
                      ? 'bg-cyan-500 text-slate-950 shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  )}
                >
                  {speed}x
                </button>
              ))}
            </div>
          </div>

          {/* Incident Telemetry Counter */}
          <div className="flex items-center space-x-6 text-xs font-mono">
            <div>
              <span className="text-slate-500">EVENT PROGRESS: </span>
              <span className="text-white font-bold">
                {steps.length > 0 ? currentIndex + 1 : 0} / {steps.length}
              </span>
            </div>
            <div>
              <span className="text-slate-500">SIMULATION CLOCK: </span>
              <span className="text-cyan-400 font-bold">
                {currentStep ? new Date(currentStep.ts * 1000).toISOString().slice(11, 19) + ' UTC' : '—'}
              </span>
            </div>
            <div>
              <span className="text-slate-500">CIRCUIT BREAKER: </span>
              <span
                className={cn(
                  'font-bold px-2 py-0.5 rounded text-[11px]',
                  currentBreakerState === 'Lockdown'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50 animate-pulse'
                    : currentBreakerState === 'Elevated'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50'
                )}
              >
                {currentBreakerState.toUpperCase()}
              </span>
            </div>
          </div>
        </div>

        {/* Timeline Visual Scrubber Bar */}
        <div className="mt-5 pt-4 border-t border-slate-800/80">
          <div className="relative">
            <input
              type="range"
              min={0}
              max={Math.max(0, steps.length - 1)}
              value={currentIndex}
              onChange={handleScrub}
              className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
            />
            {/* Markers */}
            <div className="flex justify-between items-center mt-2.5 px-1">
              {timelineMarkers.map((marker) => {
                const isActive = currentIndex >= marker.index;
                return (
                  <button
                    key={marker.label}
                    onClick={() => setCurrentIndex(Math.min(marker.index, steps.length - 1))}
                    className={cn(
                      'text-left transition-colors group cursor-pointer focus:outline-none',
                      isActive ? 'text-cyan-400' : 'text-slate-500 hover:text-slate-300'
                    )}
                  >
                    <div className="flex items-center space-x-1">
                      <span
                        className={cn(
                          'w-2 h-2 rounded-full transition-transform group-hover:scale-125',
                          isActive ? 'bg-cyan-400' : 'bg-slate-700'
                        )}
                      />
                      <span className="text-[11px] font-semibold">{marker.label}</span>
                    </div>
                    <span className="text-[9px] font-mono text-slate-500 block pl-3">
                      {marker.tag}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Split-Screen Hero Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* LEFT PANEL: Unprotected Baseline */}
        <div className="bg-slate-900/90 border border-rose-950/70 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[620px]">
          {/* Header */}
          <div className="p-4 bg-gradient-to-r from-rose-950/60 to-slate-900 border-b border-rose-900/40">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 bg-rose-500/20 rounded-lg border border-rose-500/30">
                  <Flame className="w-5 h-5 text-rose-400 animate-pulse" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                    UNPROTECTED BASELINE
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                      Blind Sign
                    </span>
                  </h3>
                  <p className="text-[11px] text-rose-300/70">
                    Hot wallet signing node with zero velocity limits or 7702 delegation checks
                  </p>
                </div>
              </div>
            </div>

            {/* Ticking Loss Counter */}
            <div className="mt-4 p-3 rounded-lg bg-black/50 border border-rose-900/50 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono text-slate-400 tracking-wider uppercase block">
                  CUMULATIVE EXPLOIT LOSS
                </span>
                <span className="text-2xl sm:text-3xl font-mono font-black text-rose-400 tracking-tight">
                  {formatFullCurrency(currentUnprotectedLoss)}
                </span>
              </div>
              <div className="text-right">
                <span className="text-[10px] font-mono text-slate-400 uppercase block">
                  DRAINED ASSETS
                </span>
                <span className="text-sm font-mono font-bold text-rose-300">
                  {formatCurrency(currentUnprotectedLoss)}
                </span>
              </div>
            </div>
          </div>

          {/* Fast Scrolling Transaction Stream */}
          <div ref={leftListRef} className="flex-1 overflow-y-auto p-3 space-y-2 font-mono text-xs">
            {visibleSteps.map((step) => {
              const chainStyle = getChainBadgeStyle(step.chain);
              const isAttack = step.scenario === 'attack';

              return (
                <div
                  key={`left-${step.request_id}`}
                  className={cn(
                    'p-2.5 rounded-lg border transition-all flex items-center justify-between',
                    isAttack
                      ? 'bg-rose-950/20 border-rose-900/40 hover:bg-rose-950/30'
                      : 'bg-slate-950/40 border-slate-800 hover:bg-slate-900/50'
                  )}
                >
                  <div className="flex items-center space-x-2.5">
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
                    <span className="text-slate-400 text-[11px]">{truncateAddress(step.wallet)}</span>
                    <span className="text-slate-600">→</span>
                    <span className="text-slate-400 text-[11px]">{truncateAddress(step.request_id)}</span>
                  </div>

                  <div className="flex items-center space-x-3">
                    <div className="text-right">
                      <span
                        className={cn(
                          'font-bold text-xs block',
                          isAttack ? 'text-rose-400' : 'text-slate-300'
                        )}
                      >
                        {step.amount_usd > 0 ? formatFullCurrency(step.amount_usd) : '7702 Auth'}
                      </span>
                      <span className="text-[10px] text-slate-500 uppercase">{step.kind}</span>
                    </div>

                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                      SIGNED
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* RIGHT PANEL: BitGuard Protected */}
        <div className="bg-slate-900/90 border border-emerald-950/70 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[620px]">
          {/* Header */}
          <div className="p-4 bg-gradient-to-r from-emerald-950/60 to-slate-900 border-b border-emerald-900/40">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 bg-emerald-500/20 rounded-lg border border-emerald-500/30">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                    BITGUARD PROTECTED
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      Firewall Active
                    </span>
                  </h3>
                  <p className="text-[11px] text-emerald-300/70">
                    Autonomous signing firewall with rolling-window limits and 7702 delegation guard
                  </p>
                </div>
              </div>
            </div>

            {/* Frozen Loss Counter & Loss Prevented Hero */}
            <div className="mt-4 p-3 rounded-lg bg-black/50 border border-emerald-900/50 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono text-slate-400 tracking-wider uppercase block">
                  HOT WALLET LOSS
                </span>
                <span
                  className={cn(
                    'text-2xl sm:text-3xl font-mono font-black tracking-tight',
                    currentProtectedLoss === 0 ? 'text-emerald-400' : 'text-amber-400'
                  )}
                >
                  {formatFullCurrency(currentProtectedLoss)}
                </span>
              </div>
              <div className="text-right">
                <span className="text-[10px] font-mono text-emerald-400 uppercase font-bold block">
                  ASSETS SAVED
                </span>
                <span className="text-base sm:text-lg font-mono font-black text-emerald-300">
                  {formatCurrency(currentLossPrevented)}{' '}
                  <span className="text-xs text-emerald-400 font-normal">
                    ({currentPreventedPct.toFixed(1)}%)
                  </span>
                </span>
              </div>
            </div>
          </div>

          {/* Tripwire Announcement Banner (When policy trips) */}
          {tripwireStep && (
            <div className="p-3 bg-rose-500/10 border-b border-rose-500/30 flex items-center justify-between text-xs animate-fadeIn">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <div>
                  <span className="font-bold text-rose-300">
                    TRIPWIRE TRIPPED AT {tripwireStep.request_id}
                  </span>
                  <span className="text-slate-300 ml-2">
                    Rule:{' '}
                    <span className="font-mono text-amber-300 font-semibold">
                      {tripwireStep.protected_decision.reasons[0]?.rule || 'policy_violation'}
                    </span>
                  </span>
                </div>
              </div>
              <div className="text-right">
                <span className="text-[10px] font-mono font-bold text-rose-300 uppercase">
                  CONTAINMENT: 0.0s
                </span>
              </div>
            </div>
          )}

          {/* Transaction Stream with Protected Decisions */}
          <div ref={rightListRef} className="flex-1 overflow-y-auto p-3 space-y-2 font-mono text-xs">
            {visibleSteps.map((step) => {
              const chainStyle = getChainBadgeStyle(step.chain);
              const decision = step.protected_decision;
              const isAllowed = decision.action === 'allow';
              const isHeld = decision.action === 'hold';
              const isDenied = decision.action === 'deny';

              return (
                <div
                  key={`right-${step.request_id}`}
                  className={cn(
                    'p-2.5 rounded-lg border transition-all flex items-center justify-between',
                    isAllowed && 'bg-slate-950/40 border-slate-800 hover:bg-slate-900/50',
                    isHeld && 'bg-amber-950/20 border-amber-900/40 hover:bg-amber-950/30',
                    isDenied && 'bg-rose-950/30 border-rose-900/60 hover:bg-rose-950/40'
                  )}
                >
                  <div className="flex items-center space-x-2.5">
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
                    <span className="text-slate-400 text-[11px]">{truncateAddress(step.wallet)}</span>
                    <span className="text-slate-600">→</span>
                    <span className="text-slate-400 text-[11px]">
                      {truncateAddress(step.request_id)}
                    </span>
                  </div>

                  <div className="flex items-center space-x-3">
                    <div className="text-right">
                      <span
                        className={cn(
                          'font-bold text-xs block',
                          isAllowed ? 'text-slate-300' : isHeld ? 'text-amber-400' : 'text-rose-400'
                        )}
                      >
                        {step.amount_usd > 0 ? formatFullCurrency(step.amount_usd) : '7702 Auth'}
                      </span>
                      <span className="text-[10px] text-slate-500 uppercase">
                        Risk: {decision.risk}/100
                      </span>
                    </div>

                    <span
                      className={cn(
                        'px-2 py-0.5 rounded text-[10px] font-bold border uppercase',
                        isAllowed && 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
                        isHeld && 'bg-amber-500/20 text-amber-300 border-amber-500/40',
                        isDenied && 'bg-rose-500/30 text-rose-200 border-rose-500/60 font-black'
                      )}
                    >
                      {decision.action}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
