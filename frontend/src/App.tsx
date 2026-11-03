import React, { useState, useEffect } from 'react';
import { Navbar, DashboardTab } from './components/Navbar';
import { ReplayView } from './pages/ReplayView';
import { LiveFeed } from './pages/LiveFeed';
import { RadarView } from './pages/RadarView';
import { PolicyLabView } from './pages/PolicyLabView';
import { ReportsView } from './pages/ReportsView';
import { ApprovalView } from './pages/ApprovalView';
import { PolicySliders } from './components/PolicySliders';
import { runReplay, resetSystem, ReplayResponse, PolicyOverrides, StepEvent, ReplayMetrics } from './api';
import { Shield, AlertCircle } from 'lucide-react';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<DashboardTab>('replay');
  const [replayData, setReplayData] = useState<ReplayResponse | null>(null);
  const [policyOverrides, setPolicyOverrides] = useState<PolicyOverrides>({
    single_tx_usd: 50_000,
    wallet_limit_usd: 100_000,
    global_limit_usd: 500_000,
    new_recipient_usd: 10_000,
    spray_threshold: 50,
  });
  const [breakerState, setBreakerState] = useState<string>('Normal');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [replayStep, setReplayStep] = useState<number>(0);
  const [isReplayPlaying, setIsReplayPlaying] = useState<boolean>(false);

  // Load initial simulation data
  const loadSimulation = async (overrides?: PolicyOverrides) => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await runReplay({ policy_overrides: overrides ?? policyOverrides });
      setReplayData(data);
      setBreakerState(data.summary.breaker_final_state);
    } catch (err: any) {
      console.warn('API fetch warning, using local simulation data fallback:', err);
      setError('Backend API offline or unreachable. Please start backend on http://localhost:8000.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSimulation();
  }, []);

  const handleReset = async () => {
    setIsLoading(true);
    try {
      await resetSystem();
      await loadSimulation();
    } catch (err: any) {
      console.error('Failed to reset system:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleApplyPolicy = () => {
    loadSimulation(policyOverrides);
  };

  const steps: StepEvent[] = replayData?.steps ?? [];
  const summary: ReplayMetrics | null = replayData?.summary ?? null;

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col font-sans">
      {/* Navbar */}
      <Navbar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        breakerState={breakerState}
        onReset={handleReset}
        isResetting={isLoading}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {error && (
          <div className="mb-6 p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-center justify-between text-xs">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-amber-400" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => loadSimulation()}
              className="px-2.5 py-1 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 rounded text-amber-200 font-semibold"
            >
              Retry
            </button>
          </div>
        )}

        {/* Tab 1: Incident Replay Split-Screen */}
        {currentTab === 'replay' && (
          <div className="space-y-6">
            <ReplayView
              steps={steps}
              summary={summary}
              onRunSimulation={() => loadSimulation()}
              isLoading={isLoading}
              onStepChange={setReplayStep}
              onPlayStateChange={setIsReplayPlaying}
            />
            {/* Embedded Policy Tuning section at the bottom for quick access */}
            <div className="pt-4">
              <PolicySliders
                overrides={policyOverrides}
                onChangeOverrides={setPolicyOverrides}
                onApply={handleApplyPolicy}
                isLoading={isLoading}
              />
            </div>
          </div>
        )}

        {/* Tab 2: Live Decision Stream */}
        {currentTab === 'feed' && (
          <LiveFeed
            steps={steps}
            currentStep={replayStep}
            isPlaying={isReplayPlaying}
          />
        )}

        {/* Tab 3: 7702 Radar */}
        {currentTab === 'radar' && <RadarView />}

        {/* Tab 4: Policy Sensitivity Lab */}
        {currentTab === 'lab' && <PolicyLabView />}

        {/* Tab 5: Cryptographic Audit & Reports */}
        {currentTab === 'reports' && <ReportsView />}

        {/* Tab 6: Quorum WebAuthn Approvals (Milestone S16) */}
        {currentTab === 'approvals' && <ApprovalView />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/80 py-4 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-500 gap-2">
          <div className="flex items-center space-x-2">
            <Shield className="w-3.5 h-3.5 text-cyan-500" />
            <span>BitGuard Autonomous Signing-Request Firewall & Incident-Replay Lab</span>
          </div>
          <div>
            <span>Modelled on the late-October 2026 Binance hot wallet exploit sequence.</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
