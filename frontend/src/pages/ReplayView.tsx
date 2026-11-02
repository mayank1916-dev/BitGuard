import React, { useState, useEffect, useRef } from 'react';
import {
  Play,
  Pause,
  RotateCcw,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Sliders,
  X,
  Send,
} from 'lucide-react';
import { StepEvent, ReplayMetrics, evaluateSigningRequest, Decision } from '../api';
import { formatCurrency, formatFullCurrency, getChainBadgeStyle, truncateAddress, cn } from '../utils';

interface ReplayViewProps {
  steps: StepEvent[];
  summary?: ReplayMetrics | null;
  onRunSimulation?: () => void;
  isLoading?: boolean;
  onStepChange?: (step: number) => void;
  onPlayStateChange?: (playing: boolean) => void;
}

export const ReplayView: React.FC<ReplayViewProps> = ({
  steps,
  onStepChange,
  onPlayStateChange,
}) => {
  const [injectedEvents, setInjectedEvents] = useState<StepEvent[]>([]);
  const events = [...steps, ...injectedEvents];
  const [currentIndex, setCurrentIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1); // 1x, 5x, 10x

  // Custom Transaction Evaluation Sandbox State
  const [isSandboxOpen, setIsSandboxOpen] = useState<boolean>(false);
  const [sandboxTx, setSandboxTx] = useState<{
    chain: string;
    wallet: string;
    kind: string;
    asset: string;
    amount_usd: number;
    to: string;
    delegate: string;
  }>({
    chain: 'ethereum',
    wallet: '0xBinanceHotETH1',
    kind: 'transfer',
    asset: 'ETH',
    amount_usd: 2500,
    to: '0x3333333333333333333333333333333333333333',
    delegate: '',
  });
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [evaluationResult, setEvaluationResult] = useState<Decision | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);

  const leftListRef = useRef<HTMLDivElement>(null);
  const rightListRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    onStepChange?.(currentIndex);
  }, [currentIndex, onStepChange]);

  useEffect(() => {
    onPlayStateChange?.(isPlaying);
  }, [isPlaying, onPlayStateChange]);

  const clearPlaybackTimer = () => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  };

  // Playback timer loop: 1x -> 400ms, 5x -> 80ms, 10x -> 30ms
  useEffect(() => {
    clearPlaybackTimer();

    if (!isPlaying || events.length === 0) return;

    let intervalTime = 400;
    if (playbackSpeed === 5) intervalTime = 80;
    else if (playbackSpeed === 10) intervalTime = 30;

    timerRef.current = setInterval(() => {
      setCurrentIndex((prev) => {
        if (prev >= events.length - 1) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, intervalTime);

    return () => clearPlaybackTimer();
  }, [isPlaying, playbackSpeed, events.length]);

  // Auto-scroll list as new steps appear
  useEffect(() => {
    if (leftListRef.current) {
      leftListRef.current.scrollTop = leftListRef.current.scrollHeight;
    }
    if (rightListRef.current) {
      rightListRef.current.scrollTop = rightListRef.current.scrollHeight;
    }
  }, [currentIndex]);

  const currentStep: StepEvent | undefined = events[currentIndex];
  const visibleSteps = events.slice(0, currentIndex + 1);

  // Simulation Clock Behavior:
  // When replay is idle or reset (!isPlaying && currentIndex === 0), display real live current time, ticking every second.
  // When replay is playing or stepped (isPlaying || currentIndex > 0), display active simulation event timestamp.
  const [liveTime, setLiveTime] = useState<string>(
    new Date().toUTCString().slice(17, 25) + " UTC"
  );

  useEffect(() => {
    if (isPlaying || currentIndex > 0) return;

    const timer = setInterval(() => {
      setLiveTime(new Date().toUTCString().slice(17, 25) + " UTC");
    }, 1000);

    return () => clearInterval(timer);
  }, [isPlaying, currentIndex]);

  const clockDisplay =
    !isPlaying && currentIndex === 0
      ? liveTime
      : new Date((events[currentIndex]?.ts ?? 1730299400) * 1000).toISOString().substr(11, 8) + " UTC";

  // In reset state (index 0 and not playing), reset loss counters to $0.00 and breaker to NORMAL
  const isResetState = currentIndex === 0 && !isPlaying;
  const currentUnprotectedLoss = isResetState ? 0 : (currentStep?.cumulative_unprotected_loss_usd ?? 0);
  const currentProtectedLoss = isResetState ? 0 : (currentStep?.cumulative_protected_loss_usd ?? 0);
  const currentLossPrevented = Math.max(0, currentUnprotectedLoss - currentProtectedLoss);
  const currentPreventedPct =
    currentUnprotectedLoss > 0 ? (currentLossPrevented / currentUnprotectedLoss) * 100 : 100;

  // Identify tripwire event if one has fired by this step
  const tripwireStep = isResetState
    ? undefined
    : visibleSteps.find(
        (s) => s.protected_decision.action === 'hold' || s.protected_decision.action === 'deny'
      );

  const currentBreakerState = isResetState
    ? 'Normal'
    : (currentStep?.protected_decision.breaker_state || 'Normal');

  // Key Incident Markers for timeline scrubber with exact target step indices
  const timelineMarkers = [
    { label: 'Baseline', step: 0, tag: 'T -600s' },
    { label: 'XRP Outflow ($120M)', step: 12, tag: 'T 0s' },
    { label: 'Multi-Chain Drain', step: 25, tag: 'T +35s' },
    { label: 'EIP-7702 Spray', step: 45, tag: 'T +110s' },
    { label: 'Massive Sweep ($2.18B)', step: 60, tag: 'T +180s' },
    { label: 'Secondary Pulls', step: 70, tag: 'T +35m' },
  ];

  const handleStart = () => {
    if (currentIndex >= events.length - 1) {
      setCurrentIndex(0);
    }
    setIsPlaying(true);
  };

  const handlePause = () => {
    clearPlaybackTimer();
    setIsPlaying(false);
  };

  const handleReset = () => {
    clearPlaybackTimer();
    setIsPlaying(false);
    setCurrentIndex(0);
    setInjectedEvents([]);
  };

  const handleScrub = (e: React.ChangeEvent<HTMLInputElement>) => {
    setCurrentIndex(Number(e.target.value));
  };

  const handleEvaluateCustomTx = async () => {
    setIsEvaluating(true);
    setEvalError(null);
    setEvaluationResult(null);
    try {
      const req = {
        id: `custom-tx-${Math.random().toString(36).substring(2, 9)}`,
        ts: Date.now() / 1000,
        chain: sandboxTx.chain,
        wallet: sandboxTx.wallet,
        kind: sandboxTx.kind,
        asset: sandboxTx.asset,
        amount_usd: Number(sandboxTx.amount_usd) || 0,
        to: sandboxTx.to || undefined,
        delegate: sandboxTx.kind === 'authorization_7702' ? sandboxTx.delegate : undefined,
        meta: { custom: true, label: 'Sandbox Simulated TX' },
      };
      const decision = await evaluateSigningRequest(req);
      setEvaluationResult(decision);
    } catch (err: any) {
      setEvalError(err?.message || 'Failed to evaluate transaction');
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleInjectTx = () => {
    if (!evaluationResult) return;
    const reqAmount = Number(sandboxTx.amount_usd) || 0;
    const prevUnprotected = events[currentIndex]?.cumulative_unprotected_loss_usd ?? 0;
    const prevProtected = events[currentIndex]?.cumulative_protected_loss_usd ?? 0;

    const newStep: StepEvent = {
      request_id: evaluationResult.request_id,
      ts: Date.now() / 1000,
      chain: sandboxTx.chain,
      wallet: sandboxTx.wallet,
      kind: sandboxTx.kind,
      asset: sandboxTx.asset,
      amount_usd: reqAmount,
      scenario: evaluationResult.action === 'deny' ? 'attack' : 'normal',
      unprotected_action: 'allow',
      protected_decision: evaluationResult,
      cumulative_unprotected_loss_usd: prevUnprotected + reqAmount,
      cumulative_protected_loss_usd:
        prevProtected + (evaluationResult.action === 'allow' ? reqAmount : 0),
    };

    const updated = [...injectedEvents, newStep];
    setInjectedEvents(updated);
    setCurrentIndex(steps.length + updated.length - 1);
    setIsSandboxOpen(false);
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

            {/* Custom TX Sandbox Trigger */}
            <button
              onClick={() => setIsSandboxOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-cyan-950/40 hover:bg-cyan-900/40 text-cyan-300 border border-cyan-800/50 font-medium text-xs transition-colors cursor-pointer"
              title="Open Custom Transaction Evaluation Sandbox"
            >
              <Sliders className="w-3.5 h-3.5 text-cyan-400" />
              <span>Simulate Custom TX</span>
            </button>
          </div>

          {/* Incident Telemetry Counter */}
          <div className="flex items-center space-x-6 text-xs font-mono">
            <div>
              <span className="text-slate-500">EVENT PROGRESS: </span>
              <span className="text-white font-bold">
                {events.length > 0 ? (currentIndex === 0 && !isPlaying ? 0 : (isPlaying ? currentIndex + 1 : currentIndex)) : 0} / {events.length}
              </span>
            </div>
            <div>
              <span className="text-slate-500">SIMULATION CLOCK: </span>
              <span className="text-cyan-400 font-bold font-mono">
                {clockDisplay}
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
              max={Math.max(0, events.length - 1)}
              value={currentIndex}
              onChange={handleScrub}
              className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
            />
            {/* Markers with progressive glow */}
            <div className="flex justify-between items-center mt-2.5 px-1">
              {timelineMarkers.map((marker) => {
                const isPassed = currentIndex >= marker.step;
                return (
                  <button
                    key={marker.label}
                    onClick={() => setCurrentIndex(Math.min(marker.step, events.length - 1))}
                    className={cn(
                      'text-left transition-colors group cursor-pointer focus:outline-none',
                      isPassed ? 'text-cyan-200 font-semibold' : 'text-slate-500 hover:text-slate-400'
                    )}
                  >
                    <div className="flex items-center space-x-1.5">
                      <span
                        className={cn(
                          'w-2 h-2 rounded-full transition-all duration-200',
                          isPassed
                            ? 'bg-cyan-400 shadow-[0_0_8px_#22d3ee]'
                            : 'bg-slate-700'
                        )}
                      />
                      <span className="text-[11px]">{marker.label}</span>
                    </div>
                    <span
                      className={cn(
                        'text-[9px] font-mono block pl-3.5 transition-colors',
                        isPassed ? 'text-cyan-400/80' : 'text-slate-500'
                      )}
                    >
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
            {currentIndex === 0 && !isPlaying ? (
              <div
                onClick={() => setIsSandboxOpen(true)}
                className="text-slate-500 text-xs text-center py-8 cursor-pointer hover:text-slate-400 transition-colors"
                title="Click to open Custom Transaction Sandbox"
              >
                Firewall standby. Click 'Start Replay' or submit a live transaction to evaluate pipeline traffic.
              </div>
            ) : (
              visibleSteps.map((step) => {
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
                      <span className="text-slate-400 text-[11px]">
                        {truncateAddress(step.request_id)}
                      </span>
                    </div>

                    <div className="flex items-center space-x-3">
                      <div className="text-right">
                        <span className="font-bold text-xs text-rose-400 block">
                          {step.amount_usd > 0 ? formatFullCurrency(step.amount_usd) : '7702 Auth'}
                        </span>
                        <span className="text-[10px] text-slate-500 uppercase">
                          {(step as any).asset ? `${(step as any).asset} Outflow` : `${step.chain.toUpperCase()} Outflow`}
                        </span>
                      </div>

                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                        SIGNED
                      </span>
                    </div>
                  </div>
                );
              })
            )}
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
            {currentIndex === 0 && !isPlaying ? (
              <div
                onClick={() => setIsSandboxOpen(true)}
                className="text-slate-500 text-xs text-center py-8 cursor-pointer hover:text-slate-400 transition-colors"
                title="Click to open Custom Transaction Sandbox"
              >
                Firewall standby. Click 'Start Replay' or submit a live transaction to evaluate pipeline traffic.
              </div>
            ) : (
              visibleSteps.map((step) => {
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
              })
            )}
          </div>
        </div>
      </div>

      {/* Custom Transaction Evaluation Sandbox Modal */}
      {isSandboxOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5 text-slate-200">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
                  <Sliders className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    Custom Transaction Evaluation Sandbox
                  </h3>
                  <p className="text-xs text-slate-400">
                    Test live signing requests against BitGuard velocity limits, delegation checks & circuit breaker
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIsSandboxOpen(false)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Quick Presets */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                Quick Scenario Presets:
              </span>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setSandboxTx({
                      chain: 'ethereum',
                      wallet: '0xBinanceHotETH1',
                      kind: 'transfer',
                      asset: 'ETH',
                      amount_usd: 2500,
                      to: '0x3333333333333333333333333333333333333333',
                      delegate: '',
                    });
                    setEvaluationResult(null);
                  }}
                  className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-emerald-400 cursor-pointer font-medium"
                >
                  ✓ Benign Transfer ($2,500)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSandboxTx({
                      chain: 'ethereum',
                      wallet: '0xBinanceHotETH1',
                      kind: 'transfer',
                      asset: 'ETH',
                      amount_usd: 75000,
                      to: '0x4444444444444444444444444444444444444444',
                      delegate: '',
                    });
                    setEvaluationResult(null);
                  }}
                  className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-amber-400 cursor-pointer font-medium"
                >
                  ⚠ Velocity Breach ($75,000)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSandboxTx({
                      chain: 'ethereum',
                      wallet: '0xBinanceHotETH1',
                      kind: 'authorization_7702',
                      asset: 'ETH',
                      amount_usd: 0,
                      to: '',
                      delegate: '0xAttackerSweeperContract00000000000000',
                    });
                    setEvaluationResult(null);
                  }}
                  className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-rose-400 cursor-pointer font-medium"
                >
                  ✕ Unapproved 7702 Delegate
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSandboxTx({
                      chain: 'tron',
                      wallet: 'TBinanceHotTRX1',
                      kind: 'transfer',
                      asset: 'USDT',
                      amount_usd: 650000,
                      to: 'TAttackerTRONAddress0000000000000000',
                      delegate: '',
                    });
                    setEvaluationResult(null);
                  }}
                  className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-purple-400 cursor-pointer font-medium"
                >
                  ⚡ Multi-Chain USDT Spike ($650k)
                </button>
              </div>
            </div>

            {/* Input Form Fields */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-mono">Chain</label>
                <select
                  value={sandboxTx.chain}
                  onChange={(e) => setSandboxTx({ ...sandboxTx, chain: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="ethereum">Ethereum</option>
                  <option value="solana">Solana</option>
                  <option value="bitcoin">Bitcoin</option>
                  <option value="tron">Tron</option>
                  <option value="arbitrum">Arbitrum</option>
                  <option value="base">Base</option>
                  <option value="optimism">Optimism</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Operation Kind</label>
                <select
                  value={sandboxTx.kind}
                  onChange={(e) => setSandboxTx({ ...sandboxTx, kind: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="transfer">transfer</option>
                  <option value="contract_call">contract_call</option>
                  <option value="authorization_7702">authorization_7702</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Signing Wallet</label>
                <input
                  type="text"
                  value={sandboxTx.wallet}
                  onChange={(e) => setSandboxTx({ ...sandboxTx, wallet: e.target.value })}
                  placeholder="0xBinanceHotETH1"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-mono">Asset & Amount (USD)</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={sandboxTx.asset}
                    onChange={(e) => setSandboxTx({ ...sandboxTx, asset: e.target.value })}
                    className="w-20 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono uppercase"
                  />
                  <input
                    type="number"
                    value={sandboxTx.amount_usd}
                    onChange={(e) => setSandboxTx({ ...sandboxTx, amount_usd: parseFloat(e.target.value) || 0 })}
                    className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              {sandboxTx.kind === 'authorization_7702' ? (
                <div className="sm:col-span-2">
                  <label className="block text-slate-400 mb-1 font-mono">EIP-7702 Delegate Contract Address</label>
                  <input
                    type="text"
                    value={sandboxTx.delegate}
                    onChange={(e) => setSandboxTx({ ...sandboxTx, delegate: e.target.value })}
                    placeholder="0xUnapprovedSweeperContract..."
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              ) : (
                <div className="sm:col-span-2">
                  <label className="block text-slate-400 mb-1 font-mono">Recipient Address (To)</label>
                  <input
                    type="text"
                    value={sandboxTx.to}
                    onChange={(e) => setSandboxTx({ ...sandboxTx, to: e.target.value })}
                    placeholder="0xDestinationAddress..."
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              )}
            </div>

            {/* Evaluate Button */}
            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={handleEvaluateCustomTx}
                disabled={isEvaluating}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-2 transition-all cursor-pointer disabled:opacity-50"
              >
                {isEvaluating ? (
                  <span>Evaluating...</span>
                ) : (
                  <>
                    <Send className="w-3.5 h-3.5" />
                    <span>Evaluate Request via BitGuard</span>
                  </>
                )}
              </button>
            </div>

            {/* Evaluation Results Banner */}
            {evalError && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                {evalError}
              </div>
            )}

            {evaluationResult && (
              <div className="mt-3 p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="text-slate-400">ACTION:</span>
                    <span
                      className={cn(
                        'px-2.5 py-0.5 rounded text-xs font-bold uppercase border',
                        evaluationResult.action === 'allow' && 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
                        evaluationResult.action === 'hold' && 'bg-amber-500/20 text-amber-300 border-amber-500/40',
                        evaluationResult.action === 'deny' && 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                      )}
                    >
                      {evaluationResult.action}
                    </span>
                  </div>

                  <div className="flex items-center space-x-4">
                    <div>
                      <span className="text-slate-400">RISK: </span>
                      <span className={cn(
                        'font-bold',
                        evaluationResult.risk === 0 ? 'text-emerald-400' : evaluationResult.risk < 70 ? 'text-amber-400' : 'text-rose-400'
                      )}>
                        {evaluationResult.risk}/100
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400">BREAKER: </span>
                      <span className="font-bold text-cyan-300">
                        {evaluationResult.breaker_state}
                      </span>
                    </div>
                  </div>
                </div>

                {evaluationResult.reasons.length > 0 && (
                  <div className="pt-2 border-t border-slate-900 space-y-1">
                    <span className="text-slate-500 text-[10px] uppercase block">Rule Violations:</span>
                    {evaluationResult.reasons.map((r, i) => (
                      <div key={i} className="text-[11px] text-amber-300/90 bg-amber-500/5 px-2 py-1 rounded border border-amber-500/20">
                        <span className="font-bold text-amber-400">{r.rule}</span>: {r.message}
                      </div>
                    ))}
                  </div>
                )}

                <div className="pt-2 flex justify-end">
                  <button
                    type="button"
                    onClick={handleInjectTx}
                    className="px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition-colors cursor-pointer"
                  >
                    Inject into Timeline Stream
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
