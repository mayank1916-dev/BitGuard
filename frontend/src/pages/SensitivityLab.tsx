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
  Play,
  RotateCcw,
  Check,
  Shield,
  Clock,
  Users,
  FileText,
  KeyRound,
  GitCompare,
  History,
} from 'lucide-react';
import {
  fetchSensitivityMatrix,
  DATA_SOURCE,
  classifyPolicy,
  runPolicyBacktest,
  listPolicies,
  getActivePolicy,
  proposePolicy,
  approvePolicy,
  activatePolicy,
  rollbackPolicy,
  PolicyClassificationPayload,
  PolicyVersionItem,
  DraftBacktestResult,
} from '../api';
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

  // 2. Active state hook for normalized sensitivity results (Demo mode)
  const [sensitivityResults, setSensitivityResults] = useState<any[]>([]);
  const [isRecalculating, setIsRecalculating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // 3. API Mode State (Milestone U8)
  const isApiMode = DATA_SOURCE === 'api';
  const [activePolicy, setActivePolicy] = useState<PolicyVersionItem | null>(null);
  const [policyVersions, setPolicyVersions] = useState<PolicyVersionItem[]>([]);
  const [classification, setClassification] = useState<PolicyClassificationPayload | null>(null);
  const [backtestResult, setBacktestResult] = useState<DraftBacktestResult | null>(null);
  const [isBacktesting, setIsBacktesting] = useState<boolean>(false);
  const [isActionLoading, setIsActionLoading] = useState<boolean>(false);
  const [actionNotice, setActionNotice] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [diffViewMode, setDiffViewMode] = useState<'structured' | 'unified'>('structured');
  const [pendingDraftVersion, setPendingDraftVersion] = useState<PolicyVersionItem | null>(null);

  // User role state for testing governance & RBAC
  const [currentRole, setCurrentRole] = useState<'Operator' | 'Approver' | 'SecOps' | 'Admin'>('Operator');
  const [currentUserId, setCurrentUserId] = useState<string>('usr-operator-01');
  const [cooldownRemaining, setCooldownRemaining] = useState<number>(0);

  const debounceTimerRef = useRef<NodeJS.Timeout | null>(null);
  const latestReqIdRef = useRef<number>(0);

  // Execute recalculation against backend & normalize response keys (Demo mode)
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

  // API Mode: Load active policy and version history
  const loadPolicyData = async () => {
    try {
      const [active, history] = await Promise.all([
        getActivePolicy().catch(() => null),
        listPolicies(20).catch(() => []),
      ]);
      if (active) {
        setActivePolicy(active);
      }
      if (history && history.length > 0) {
        setPolicyVersions(history);
      }
    } catch (err) {
      console.warn('Error loading policy history:', err);
    }
  };

  // API Mode: Re-classify draft policy whenever sliders update
  const executeClassification = async (sTx: number, wLimit: number, gLimit: number, uLimit: number) => {
    try {
      const draft = {
        single_tx_usd: sTx,
        wallet_limit_usd: wLimit,
        global_limit_usd: gLimit,
        new_recipient_usd: uLimit,
      };
      const result = await classifyPolicy(draft, activePolicy?.id);
      setClassification(result);
    } catch (err: any) {
      console.warn('Policy classification warning:', err);
    }
  };

  // Listen to slider changes with debounce
  useEffect(() => {
    if (!isApiMode) {
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
    } else {
      // In API Mode, update classification
      executeClassification(singleTx, walletLimit, globalLimit, unseenLimit);
    }
  }, [singleTx, walletLimit, globalLimit, unseenLimit, isApiMode]);

  // Initial load for API mode
  useEffect(() => {
    if (isApiMode) {
      loadPolicyData();
      executeClassification(singleTx, walletLimit, globalLimit, unseenLimit);
    }
  }, [isApiMode]);

  // Cooldown countdown tick
  useEffect(() => {
    if (cooldownRemaining <= 0) return;
    const interval = setInterval(() => {
      setCooldownRemaining((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(interval);
  }, [cooldownRemaining]);

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

  // API Mode Action: Run Backtest on Draft Policy (Milestone S22 / F8)
  const handleRunBacktest = async () => {
    setIsBacktesting(true);
    setActionNotice(null);
    try {
      const draft = {
        single_tx_usd: singleTx,
        wallet_limit_usd: walletLimit,
        global_limit_usd: globalLimit,
        new_recipient_usd: unseenLimit,
      };
      const report = await runPolicyBacktest(draft, ['split_under_limit', 'rapid_velocity']);
      setBacktestResult(report);
      setActionNotice({
        type: 'success',
        text: `Backtest completed on S22 engine. Report ID: ${report.id}. Holds: ${report.held_count}, False Positives: ${report.estimated_false_positives}, Synthetic Loss Contained: ${formatCurrency(report.synthetic_loss_prevented_usd)}.`,
      });

      // Reload policies to fetch draft version if created
      await loadPolicyData();
    } catch (err: any) {
      console.error('Backtest error:', err);
      setActionNotice({ type: 'error', text: err.message || 'Failed to execute backtest on draft policy.' });
    } finally {
      setIsBacktesting(false);
    }
  };

  // API Mode Action: Instant Tightening Activation (Single person, instant)
  const handleActivateTightening = async () => {
    setIsActionLoading(true);
    setActionNotice(null);
    try {
      const draftDoc = classification?.draft_doc || {
        version: `v1.${policyVersions.length + 1}.0-tighten`,
        limits: {
          global_daily_usd: globalLimit,
          global_single_tx_usd: singleTx,
          global_velocity_limit_usd: walletLimit,
          wallet_daily_usd: { default: walletLimit },
        },
        thresholds: {
          single_tx_usd: singleTx,
          hold_score: 50,
          new_recipient_usd: unseenLimit,
        },
      };

      // Propose version
      const proposed = await proposePolicy({
        version: draftDoc.version || `v1.${policyVersions.length + 1}.0`,
        content: draftDoc,
      });

      // Instant activate
      const activated = await activatePolicy(proposed.id);
      setActivePolicy(activated);
      setPendingDraftVersion(null);
      await loadPolicyData();

      setActionNotice({
        type: 'success',
        text: `Tightening policy '${activated.version}' activated instantly by ${currentUserId}. Engines hot-reloaded.`,
      });
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err.message || 'Activation failed.' });
    } finally {
      setIsActionLoading(false);
    }
  };

  // API Mode Action: Propose Loosening Draft
  const handleProposeLoosening = async () => {
    setIsActionLoading(true);
    setActionNotice(null);
    try {
      if (!backtestResult?.id) {
        setActionNotice({
          type: 'error',
          text: 'Empirical backtest report is required before proposing a loosening policy. Click "Run backtest" first.',
        });
        return;
      }

      const draftDoc = classification?.draft_doc || {
        version: `v1.${policyVersions.length + 1}.0-loosen`,
        limits: {
          global_daily_usd: globalLimit,
          global_single_tx_usd: singleTx,
          global_velocity_limit_usd: walletLimit,
        },
        thresholds: {
          single_tx_usd: singleTx,
          hold_score: 60,
          new_recipient_usd: unseenLimit,
        },
      };

      const proposed = await proposePolicy({
        version: draftDoc.version || `v1.${policyVersions.length + 1}.0-loosen`,
        content: draftDoc,
        backtest_report_id: backtestResult.id,
      });

      setPendingDraftVersion(proposed);
      setCooldownRemaining(60);
      await loadPolicyData();

      setActionNotice({
        type: 'info',
        text: `Loosening policy proposed (${proposed.version}). Governance requirements: 2 WebAuthn approvers + 60s cooldown.`,
      });
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err.message || 'Failed to propose loosening policy.' });
    } finally {
      setIsActionLoading(false);
    }
  };

  // API Mode Action: WebAuthn Approval (Separation of duties: never author)
  const handleApproveWebAuthn = async () => {
    if (!pendingDraftVersion) return;
    setIsActionLoading(true);
    setActionNotice(null);
    try {
      if (currentUserId === pendingDraftVersion.author) {
        setActionNotice({
          type: 'error',
          text: 'Separation of duties violation: The policy author cannot approve their own loosening change.',
        });
        return;
      }

      const updated = await approvePolicy(pendingDraftVersion.id);
      setPendingDraftVersion(updated);
      await loadPolicyData();

      setActionNotice({
        type: 'success',
        text: `WebAuthn signature submitted by ${currentUserId}. Total approvals: ${updated.approvals.length} / 2.`,
      });
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err.message || 'WebAuthn approval signature rejected.' });
    } finally {
      setIsActionLoading(false);
    }
  };

  // API Mode Action: Rollback to previous version
  const handleRollback = async (targetVersionId: string) => {
    if (currentRole !== 'Admin' && currentRole !== 'SecOps') {
      setActionNotice({
        type: 'error',
        text: 'Access Denied: Only Admin or SecOps roles are authorized to execute policy rollback.',
      });
      return;
    }

    setIsActionLoading(true);
    setActionNotice(null);
    try {
      const restored = await rollbackPolicy(targetVersionId, `Operator rollback triggered by ${currentUserId}`);
      setActivePolicy(restored);
      await loadPolicyData();
      setActionNotice({
        type: 'success',
        text: `Rollback successful. Active policy reverted to ${restored.version}. Engines hot-reloaded.`,
      });
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err.message || 'Rollback failed.' });
    } finally {
      setIsActionLoading(false);
    }
  };

  // Baseline point
  const baselinePoint = sensitivityResults.find(
    (p) => p.multiplier === '1x' || p.multiplier === '1.0x' || p.multiplier === 1 || p.multiplier === 1.0
  );

  const badgeType = classification?.badge || 'TIGHTENS';
  const isTighten = badgeType === 'TIGHTENS';
  const isLoosen = badgeType === 'LOOSENS' || badgeType === 'MIXED';
  const isAuthor = pendingDraftVersion ? currentUserId === pendingDraftVersion.author : false;
  const approvalsCount = pendingDraftVersion?.approvals?.length ?? 0;
  const canActivateLoosening = isLoosen && pendingDraftVersion && approvalsCount >= 2 && cooldownRemaining <= 0;

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
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-wide">
                  Policy Sensitivity Lab & Frontier Tuning
                </h2>
                {isApiMode ? (
                  <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-500/50 text-cyan-300 font-mono font-bold flex items-center gap-1.5">
                    <Shield className="w-3 h-3 text-cyan-400" />
                    <span>API Governance Mode (S20/S22)</span>
                  </span>
                ) : (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/50 text-cyan-300 font-mono">
                    Live Dynamic Recalculation (150ms)
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {isApiMode
                  ? 'Adjust sliders to edit a DRAFT policy. Run empirical backtests (S22), review cryptographic diffs, and enforce asymmetric activation.'
                  : 'Adjust any of the 4 sliders to dynamically evaluate the risk frontier: Capital Saved ($) vs. False Positives (Txs Held).'}
              </p>
            </div>
          </div>

          {/* User Role Switcher for API Mode Governance Testing */}
          {isApiMode && (
            <div className="flex items-center space-x-2 bg-slate-950/80 p-1.5 rounded-lg border border-slate-800 text-xs">
              <span className="text-slate-400 font-mono pl-1 text-[11px]">Actor:</span>
              <select
                value={`${currentRole}:${currentUserId}`}
                onChange={(e) => {
                  const [r, u] = e.target.value.split(':');
                  setCurrentRole(r as any);
                  setCurrentUserId(u);
                }}
                className="bg-slate-900 border border-slate-700 text-cyan-300 rounded px-2 py-1 text-xs font-mono focus:outline-none"
              >
                <option value="Operator:usr-operator-01">Operator (usr-operator-01)</option>
                <option value="Approver:usr-approver-01">Approver (usr-approver-01)</option>
                <option value="Approver:usr-approver-02">Approver (usr-approver-02)</option>
                <option value="SecOps:usr-secops-01">SecOps (usr-secops-01)</option>
                <option value="Admin:usr-admin-01">Admin (usr-admin-01)</option>
              </select>
            </div>
          )}

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

      {actionNotice && (
        <div
          className={cn(
            'p-4 rounded-xl border flex items-center justify-between text-xs',
            actionNotice.type === 'success' && 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300',
            actionNotice.type === 'error' && 'bg-rose-500/10 border-rose-500/30 text-rose-300',
            actionNotice.type === 'info' && 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
          )}
        >
          <div className="flex items-center space-x-2">
            {actionNotice.type === 'success' && <Check className="w-4 h-4 text-emerald-400 shrink-0" />}
            {actionNotice.type === 'error' && <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />}
            {actionNotice.type === 'info' && <Shield className="w-4 h-4 text-cyan-400 shrink-0" />}
            <span>{actionNotice.text}</span>
          </div>
          <button onClick={() => setActionNotice(null)} className="text-slate-400 hover:text-white font-bold ml-4">
            ×
          </button>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-center space-x-2 text-xs">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Frontier Chart Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div>
            <div className="flex items-center gap-2.5">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Exchange Risk Frontier: Capital Saved ($B) vs. False Positives (Txs Held)
              </h3>
              {isApiMode ? (
                <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-500/50 text-[11px] font-mono text-cyan-300">
                  <FileText className="w-3 h-3 text-cyan-400" />
                  <span>Active Baseline: {activePolicy?.version || 'v1.0.0'}</span>
                </span>
              ) : isRecalculating ? (
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
              Left Axis (Teal Area): Loss contained in $ Billions. Right Axis (Amber Line): Normal retail customer withdrawals held for review.
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
          <ResponsiveContainer
            key={`chart-render-${sensitivityResults.length}-${singleTx}-${walletLimit}-${globalLimit}-${unseenLimit}`}
            width="100%"
            height={320}
          >
            <ComposedChart
              data={
                sensitivityResults.length > 0
                  ? sensitivityResults
                  : [
                      { multiplier: '0.25x', capitalSaved: 4.39e9, falsePositives: 18, singleTxCap: 12500, breakerState: 'NORMAL' },
                      { multiplier: '0.5x', capitalSaved: 4.39e9, falsePositives: 8, singleTxCap: 25000, breakerState: 'NORMAL' },
                      { multiplier: '1.0x', capitalSaved: 4.39e9, falsePositives: backtestResult?.estimated_false_positives ?? 1, singleTxCap: singleTx, breakerState: 'NORMAL' },
                      { multiplier: '2.0x', capitalSaved: 4.35e9, falsePositives: 0, singleTxCap: singleTx * 2, breakerState: 'NORMAL' },
                      { multiplier: '5.0x', capitalSaved: 3.8e9, falsePositives: 0, singleTxCap: singleTx * 5, breakerState: 'NORMAL' },
                    ]
              }
              margin={{ top: 10, right: 20, left: 10, bottom: 0 }}
            >
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
              <YAxis
                yAxisId="left"
                stroke="#06b6d4"
                tick={{ fill: '#06b6d4', fontSize: 11, fontFamily: 'monospace' }}
                tickFormatter={(v) => (v >= 1e9 ? `$${(v / 1e9).toFixed(1)}B` : v >= 1e6 ? `$${(v / 1e6).toFixed(0)}M` : `$${v}`)}
                domain={[0, 'auto']}
              />
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

      {/* Interactive Controls & Policy Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Sliders for Draft Limits */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 mb-4 border-b border-slate-800">
              <div className="flex items-center space-x-2 text-white font-bold text-sm">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span>{isApiMode ? 'Draft Policy Parameter Tuning' : 'Base Limit Tuning (1.0x Reference)'}</span>
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

            {/* Run Backtest Button (Task U8) */}
            {isApiMode && (
              <div className="mt-6 pt-4 border-t border-slate-800">
                <button
                  onClick={handleRunBacktest}
                  disabled={isBacktesting}
                  className="w-full py-2.5 px-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg font-bold text-xs flex items-center justify-center space-x-2 shadow-lg shadow-cyan-950/40 cursor-pointer disabled:opacity-50 transition-all"
                >
                  {isBacktesting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Streaming S22 Backtest Replay...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-current" />
                      <span>Run backtest (S22 Engine)</span>
                    </>
                  )}
                </button>
              </div>
            )}
          </div>

          {/* Current Baseline Status Callout */}
          <div className="mt-6 p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300">
            <div className="flex items-center justify-between font-bold mb-1">
              <div className="flex items-center space-x-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>{isApiMode ? 'S22 Backtest Result Summary' : 'Current 1.0x Baseline Status'}</span>
              </div>
              <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border border-emerald-500/40 bg-emerald-500/20 text-emerald-300 uppercase">
                {isApiMode ? 'REPORTED' : 'SYNTHETIC'}
              </span>
            </div>
            <p className="text-[11px] text-emerald-200/80 leading-relaxed">
              {isApiMode && backtestResult ? (
                <>
                  Reduces and contains{' '}
                  <strong>{formatCurrency(backtestResult.synthetic_loss_prevented_usd)}</strong> of synthetic exploit loss (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection)
                  with <strong>{backtestResult.estimated_false_positives} false positive hold(s)</strong> and{' '}
                  <strong>{backtestResult.held_count} total hold(s)</strong> across {backtestResult.total_events} requests.
                </>
              ) : baselinePoint ? (
                <>
                  Reduces and contains <strong>{formatCurrency(baselinePoint.capitalSaved)} ({((baselinePoint.capitalSaved / 4.39e9) * 100).toFixed(1)}%)</strong> of exploit loss (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection) with <strong>{baselinePoint.falsePositives} false positive hold(s)</strong>.
                </>
              ) : (
                'Recalculating status...'
              )}
            </p>
          </div>
        </div>

        {/* Right 2 Columns: Policy Editor & Governance Panel in API Mode, or Matrix in Demo Mode */}
        {isApiMode ? (
          <div className="lg:col-span-2 space-y-6">
            {/* Policy Editor Panel (Task U8) */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 mb-4 border-b border-slate-800 gap-3">
                <div className="flex items-center space-x-2">
                  <GitCompare className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-sm font-bold text-white tracking-wide">
                    Policy Editor & Asymmetric Evolution
                  </h4>
                </div>

                {/* Classification Badge from API */}
                <div className="flex items-center space-x-2">
                  <span className="text-xs text-slate-400 font-mono">Classification:</span>
                  <span
                    className={cn(
                      'px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider border uppercase',
                      badgeType === 'TIGHTENS' && 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
                      badgeType === 'LOOSENS' && 'bg-amber-500/20 text-amber-300 border-amber-500/40',
                      badgeType === 'MIXED' && 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                    )}
                  >
                    {badgeType}
                  </span>
                </div>
              </div>

              {/* Diff View Tabs */}
              <div className="flex items-center justify-between mb-3 text-xs">
                <span className="text-slate-400 font-mono">Diff: Draft vs. Active ({activePolicy?.version || 'v1.0.0'})</span>
                <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800 font-mono text-[11px]">
                  <button
                    onClick={() => setDiffViewMode('structured')}
                    className={cn(
                      'px-2.5 py-0.5 rounded transition-colors',
                      diffViewMode === 'structured' ? 'bg-cyan-900/60 text-cyan-200' : 'text-slate-400 hover:text-white'
                    )}
                  >
                    Structured Diff
                  </button>
                  <button
                    onClick={() => setDiffViewMode('unified')}
                    className={cn(
                      'px-2.5 py-0.5 rounded transition-colors',
                      diffViewMode === 'unified' ? 'bg-cyan-900/60 text-cyan-200' : 'text-slate-400 hover:text-white'
                    )}
                  >
                    Unified Text Diff
                  </button>
                </div>
              </div>

              {/* Diff Content Box */}
              {diffViewMode === 'structured' ? (
                <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60 mb-5">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="px-3.5 py-2">POLICY FIELD</th>
                        <th className="px-3.5 py-2">ACTIVE BASELINE</th>
                        <th className="px-3.5 py-2">PROPOSED DRAFT</th>
                        <th className="px-3.5 py-2">DIRECTION</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-200">
                      <tr>
                        <td className="px-3.5 py-2 text-slate-300">Single TX Limit (USD)</td>
                        <td className="px-3.5 py-2 text-slate-400">$50,000</td>
                        <td className="px-3.5 py-2 font-bold text-cyan-300">{formatFullCurrency(singleTx)}</td>
                        <td className="px-3.5 py-2">
                          <span
                            className={cn(
                              'text-[10px] px-1.5 py-0.5 rounded font-bold',
                              singleTx < 50_000
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : singleTx > 50_000
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-slate-800 text-slate-400'
                            )}
                          >
                            {singleTx < 50_000 ? 'TIGHTEN' : singleTx > 50_000 ? 'LOOSEN' : 'UNCHANGED'}
                          </span>
                        </td>
                      </tr>
                      <tr>
                        <td className="px-3.5 py-2 text-slate-300">Wallet Velocity Cap (1h)</td>
                        <td className="px-3.5 py-2 text-slate-400">$100,000</td>
                        <td className="px-3.5 py-2 font-bold text-cyan-300">{formatFullCurrency(walletLimit)}</td>
                        <td className="px-3.5 py-2">
                          <span
                            className={cn(
                              'text-[10px] px-1.5 py-0.5 rounded font-bold',
                              walletLimit < 100_000
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : walletLimit > 100_000
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-slate-800 text-slate-400'
                            )}
                          >
                            {walletLimit < 100_000 ? 'TIGHTEN' : walletLimit > 100_000 ? 'LOOSEN' : 'UNCHANGED'}
                          </span>
                        </td>
                      </tr>
                      <tr>
                        <td className="px-3.5 py-2 text-slate-300">Global Multi-Chain Cap</td>
                        <td className="px-3.5 py-2 text-slate-400">$500,000</td>
                        <td className="px-3.5 py-2 font-bold text-cyan-300">{formatFullCurrency(globalLimit)}</td>
                        <td className="px-3.5 py-2">
                          <span
                            className={cn(
                              'text-[10px] px-1.5 py-0.5 rounded font-bold',
                              globalLimit < 500_000
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : globalLimit > 500_000
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-slate-800 text-slate-400'
                            )}
                          >
                            {globalLimit < 500_000 ? 'TIGHTEN' : globalLimit > 500_000 ? 'LOOSEN' : 'UNCHANGED'}
                          </span>
                        </td>
                      </tr>
                      <tr>
                        <td className="px-3.5 py-2 text-slate-300">Unseen Recipient Cap</td>
                        <td className="px-3.5 py-2 text-slate-400">$10,000</td>
                        <td className="px-3.5 py-2 font-bold text-cyan-300">{formatFullCurrency(unseenLimit)}</td>
                        <td className="px-3.5 py-2">
                          <span
                            className={cn(
                              'text-[10px] px-1.5 py-0.5 rounded font-bold',
                              unseenLimit < 10_000
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : unseenLimit > 10_000
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-slate-800 text-slate-400'
                            )}
                          >
                            {unseenLimit < 10_000 ? 'TIGHTEN' : unseenLimit > 10_000 ? 'LOOSEN' : 'UNCHANGED'}
                          </span>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto max-h-48 mb-5">
                  <pre className="text-slate-300 whitespace-pre-wrap">{classification?.text_diff || 'No differences detected.'}</pre>
                </div>
              )}

              {/* Action Section: Tightening vs Loosening Governance */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                {isTighten ? (
                  // Tightening: Single person, instant activation
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Instant Tightening Eligible (Invariant #6)</span>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        Tightening or lockdown takes effect immediately with a single authorized signature. No cooldown or quorum required.
                      </p>
                    </div>

                    <button
                      onClick={handleActivateTightening}
                      disabled={isActionLoading}
                      className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold text-xs flex items-center justify-center space-x-2 shadow-lg shadow-emerald-950/40 cursor-pointer disabled:opacity-50 transition-all shrink-0"
                    >
                      {isActionLoading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Activating...</span>
                        </>
                      ) : (
                        <>
                          <Check className="w-4 h-4" />
                          <span>Activate now</span>
                        </>
                      )}
                    </button>
                  </div>
                ) : (
                  // Loosening: Requirements (2 approvers, cool-down, backtest report) + WebAuthn approval
                  <div className="space-y-4">
                    <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                      <div className="flex items-center space-x-2 text-amber-400 font-bold text-xs">
                        <Shield className="w-4 h-4" />
                        <span>Loosening Policy Requirements (Invariant #6)</span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-400">
                        Dual-Control Quorum & Cool-Down
                      </span>
                    </div>

                    {/* Requirements Matrix */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                      {/* Req 1: 2 Approvers */}
                      <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                        <div className="flex items-center justify-between text-slate-400 mb-1">
                          <span className="flex items-center gap-1.5">
                            <Users className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Approvers</span>
                          </span>
                          <span
                            className={cn(
                              'px-1.5 py-0.2 rounded text-[10px] font-bold',
                              approvalsCount >= 2 ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'
                            )}
                          >
                            {approvalsCount} / 2
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-300 font-sans">
                          {approvalsCount >= 2 ? 'Dual-control quorum satisfied' : 'Requires 2 distinct approvers'}
                        </span>
                      </div>

                      {/* Req 2: Cool-down */}
                      <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                        <div className="flex items-center justify-between text-slate-400 mb-1">
                          <span className="flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-amber-400" />
                            <span>Cool-Down</span>
                          </span>
                          <span className="text-[11px] font-bold text-amber-300">
                            {cooldownRemaining > 0 ? `${cooldownRemaining}s` : '0s (Ready)'}
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-300 font-sans">
                          {cooldownRemaining > 0 ? 'Cool-down period in progress' : 'Cool-down delay satisfied'}
                        </span>
                      </div>

                      {/* Req 3: Attached Backtest Report */}
                      <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                        <div className="flex items-center justify-between text-slate-400 mb-1">
                          <span className="flex items-center gap-1.5">
                            <FileText className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Backtest</span>
                          </span>
                          <span
                            className={cn(
                              'px-1.5 py-0.2 rounded text-[10px] font-bold',
                              backtestResult ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
                            )}
                          >
                            {backtestResult ? 'ATTACHED' : 'MISSING'}
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-300 font-sans truncate block">
                          {backtestResult ? backtestResult.id : 'Run backtest above to attach'}
                        </span>
                      </div>
                    </div>

                    {/* Action Buttons for Loosening */}
                    <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                      {!pendingDraftVersion ? (
                        <button
                          onClick={handleProposeLoosening}
                          disabled={isActionLoading || !backtestResult}
                          className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg font-bold text-xs flex items-center space-x-2 cursor-pointer disabled:opacity-50 transition-all"
                        >
                          <Shield className="w-4 h-4" />
                          <span>Submit Loosening Proposal for Quorum</span>
                        </button>
                      ) : (
                        <div className="flex items-center space-x-3 w-full justify-between">
                          <div className="text-[11px] text-slate-400">
                            Draft <span className="font-mono text-cyan-300">{pendingDraftVersion.version}</span> proposed by{' '}
                            <span className="font-mono text-slate-300">{pendingDraftVersion.author}</span>.
                          </div>

                          <div className="flex items-center space-x-2">
                            {/* WebAuthn Approval Button */}
                            <button
                              onClick={handleApproveWebAuthn}
                              disabled={isActionLoading || isAuthor || approvalsCount >= 2}
                              title={isAuthor ? 'Author cannot approve their own change (Separation of duties)' : ''}
                              className={cn(
                                'px-4 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition-all',
                                isAuthor
                                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                                  : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-950/40 cursor-pointer'
                              )}
                            >
                              <KeyRound className="w-4 h-4" />
                              <span>{isAuthor ? 'Author cannot approve' : 'Approve with WebAuthn'}</span>
                            </button>

                            {/* Final Activate Loosening */}
                            {canActivateLoosening && (
                              <button
                                onClick={async () => {
                                  try {
                                    setIsActionLoading(true);
                                    const act = await activatePolicy(pendingDraftVersion.id);
                                    setActivePolicy(act);
                                    setPendingDraftVersion(null);
                                    await loadPolicyData();
                                    setActionNotice({ type: 'success', text: `Loosening policy '${act.version}' activated.` });
                                  } catch (err: any) {
                                    setActionNotice({ type: 'error', text: err.message || 'Activation failed.' });
                                  } finally {
                                    setIsActionLoading(false);
                                  }
                                }}
                                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold text-xs flex items-center space-x-1.5 cursor-pointer"
                              >
                                <Check className="w-4 h-4" />
                                <span>Activate Loosening</span>
                              </button>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Version History & Rollback Card */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
              <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
                <div className="flex items-center space-x-2">
                  <History className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-sm font-bold text-white tracking-wide">
                    Policy Version History & Cryptographic Release Log
                  </h4>
                </div>
                <span className="text-xs font-mono text-slate-400">
                  {policyVersions.length} Recorded Releases
                </span>
              </div>

              <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/40">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="px-3.5 py-2">VERSION</th>
                      <th className="px-3.5 py-2">STATUS</th>
                      <th className="px-3.5 py-2">CLASSIFICATION</th>
                      <th className="px-3.5 py-2">AUTHOR</th>
                      <th className="px-3.5 py-2">TIMESTAMP</th>
                      <th className="px-3.5 py-2 text-right">ACTION</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-200">
                    {policyVersions.map((ver) => {
                      const isActive = ver.status === 'ACTIVE';
                      return (
                        <tr key={ver.id} className={cn('hover:bg-slate-800/30 transition-colors', isActive && 'bg-cyan-500/10 font-bold')}>
                          <td className="px-3.5 py-2 text-slate-200 flex items-center gap-1.5">
                            <span>{ver.version}</span>
                            {isActive && (
                              <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold">
                                ACTIVE
                              </span>
                            )}
                          </td>
                          <td className="px-3.5 py-2">
                            <span
                              className={cn(
                                'text-[10px] px-2 py-0.5 rounded font-bold uppercase',
                                ver.status === 'ACTIVE'
                                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                                  : ver.status === 'PENDING'
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                  : 'bg-slate-800 text-slate-400 border border-slate-700'
                              )}
                            >
                              {ver.status}
                            </span>
                          </td>
                          <td className="px-3.5 py-2">
                            <span
                              className={cn(
                                'text-[10px] px-1.5 py-0.5 rounded font-bold',
                                ver.change_type === 'TIGHTEN' ? 'text-emerald-400' : 'text-amber-400'
                              )}
                            >
                              {ver.change_type}
                            </span>
                          </td>
                          <td className="px-3.5 py-2 text-slate-400 truncate max-w-[120px]">{ver.author}</td>
                          <td className="px-3.5 py-2 text-slate-400 text-[11px]">
                            {new Date(ver.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </td>
                          <td className="px-3.5 py-2 text-right">
                            {!isActive && (
                              <button
                                onClick={() => handleRollback(ver.id)}
                                disabled={isActionLoading || (currentRole !== 'Admin' && currentRole !== 'SecOps')}
                                title={currentRole !== 'Admin' && currentRole !== 'SecOps' ? 'Rollback requires Admin or SecOps role' : 'Rollback active policy to this version'}
                                className={cn(
                                  'px-2.5 py-1 text-[11px] font-semibold rounded transition-all cursor-pointer inline-flex items-center space-x-1',
                                  currentRole === 'Admin' || currentRole === 'SecOps'
                                    ? 'bg-rose-500/10 border border-rose-500/30 text-rose-300 hover:bg-rose-500/20'
                                    : 'bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed opacity-60'
                                )}
                              >
                                <RotateCcw className="w-3 h-3" />
                                <span>Rollback</span>
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        ) : (
          // Demo Mode: Matrix Data Table
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
        )}
      </div>
    </div>
  );
};

export const PolicyLabView = SensitivityLab;
export default SensitivityLab;
