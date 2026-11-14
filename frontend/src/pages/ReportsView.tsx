import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  FileDown,
  RefreshCw,
  Lock,
  Flame,
  AlertTriangle,
  History,
  Hash,
  ChevronDown,
  ChevronUp,
  Clock,
  CheckCircle2,
  FileText,
  Calendar,
  Download,
  AlertCircle,
} from 'lucide-react';
import {
  DATA_SOURCE,
  fetchAuditRecords,
  verifyAuditIntegrity,
  simulateAuditTamper,
  resetAuditChain,
  getReportDownloadUrl,
  AuditRecord,
  verifyAuditLedger,
  fetchAuditEntries,
  triggerManualAnchor,
  listIncidents,
  exportIncidentReport,
  exportMonthlyReport,
  exportPolicyHistoryReport,
  AuditVerifyResult,
  IncidentItem,
} from '../api';
import { cn } from '../utils';

export const ReportsView: React.FC = () => {
  const isApiMode = DATA_SOURCE === 'api';

  // Demo mode state
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [rootHash, setRootHash] = useState<string>('');
  const [isValid, setIsValid] = useState<boolean>(true);
  const [corruptedIndex, setCorruptedIndex] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isActionLoading, setIsActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // API mode state (Milestone U9 / S35)
  const [apiAuditVerify, setApiAuditVerify] = useState<AuditVerifyResult | null>(null);
  const [firstBadSeq, setFirstBadSeq] = useState<number | null>(null);
  const [lastAnchorTime, setLastAnchorTime] = useState<string | null>(null);
  const [lastAnchorStatus, setLastAnchorStatus] = useState<string>('PENDING');
  const [lastAnchorUri, setLastAnchorUri] = useState<string | null>(null);
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [expandedIncidentId, setExpandedIncidentId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('inc-7702-drain-01');
  const [reportYear, setReportYear] = useState<number>(2026);
  const [reportMonth, setReportMonth] = useState<number>(11);
  const [policyVersionFilter, setPolicyVersionFilter] = useState<string>('');
  const [exportingType, setExportingType] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadAuditData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      if (isApiMode) {
        // API Mode: Call /v1/audit/verify, /v1/audit/entries, /v1/incidents
        const [verifyRes, entriesRes, incidentsRes] = await Promise.all([
          verifyAuditLedger().catch((e) => {
            console.warn('Audit verify error:', e);
            return null;
          }),
          fetchAuditEntries(50).catch((e) => {
            console.warn('Audit entries error:', e);
            return [];
          }),
          listIncidents().catch((e) => {
            console.warn('Incidents error:', e);
            return [];
          }),
        ]);

        if (verifyRes) {
          setApiAuditVerify(verifyRes);
          setIsValid(verifyRes.ok);
          setFirstBadSeq(verifyRes.first_bad_seq);
          if (verifyRes.last_anchor) {
            setLastAnchorStatus('ANCHORED');
            setLastAnchorUri(verifyRes.last_anchor.storage_uri || null);
            if (verifyRes.last_anchor.ts) {
              setLastAnchorTime(
                new Date(verifyRes.last_anchor.ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
              );
            }
          } else {
            setLastAnchorStatus('PENDING');
            setLastAnchorTime(null);
            setLastAnchorUri(null);
          }
        }

        if (entriesRes && entriesRes.length > 0) {
          const mapped: AuditRecord[] = entriesRes.map((e) => ({
            index: e.seq,
            timestamp: e.ts,
            request_id: e.payload?.request_id || e.payload?.tx_id || `req-${e.seq}`,
            action: (e.payload?.verdict || e.payload?.action || e.action.split(':')[0] || 'allow').toLowerCase(),
            risk: Number(e.payload?.risk_score ?? e.payload?.score ?? 15),
            rule_hits: Array.isArray(e.payload?.reasons)
              ? e.payload.reasons
              : e.action
              ? [e.action]
              : [],
            prev_hash: e.prev_hash,
            entry_hash: e.entry_hash,
            data_label: e.data_label || 'REAL',
          }));
          setRecords(mapped);
          setRootHash(entriesRes[entriesRes.length - 1]?.entry_hash || '0'.repeat(64));
        }

        if (incidentsRes && incidentsRes.length > 0) {
          setIncidents(incidentsRes);
          if (!selectedIncidentId) {
            setSelectedIncidentId(incidentsRes[0].id);
          }
        }
      } else {
        // Demo Mode: Built-in simulation behavior
        const [recordsRes, verifyRes] = await Promise.all([
          fetchAuditRecords(),
          verifyAuditIntegrity(),
        ]);
        setRecords(recordsRes.records);
        setRootHash(recordsRes.root_hash);
        setIsValid(verifyRes.valid);
        setCorruptedIndex(verifyRes.corrupted_index);
      }
    } catch (err: any) {
      console.error('Error fetching audit records:', err);
      setError('Failed to fetch cryptographic audit ledger from backend.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAuditData();

    // In API mode: audit tick periodically refreshes verification status
    if (isApiMode) {
      const interval = setInterval(async () => {
        try {
          const v = await verifyAuditLedger();
          setApiAuditVerify(v);
          setIsValid(v.ok);
          setFirstBadSeq(v.first_bad_seq);
        } catch {
          // ignore background polling glitches
        }
      }, 5000);
      return () => clearInterval(interval);
    }
  }, [isApiMode]);

  // Demo Mode Handlers
  const handleSimulateTamper = async () => {
    setIsActionLoading(true);
    try {
      await simulateAuditTamper();
      const verifyRes = await verifyAuditIntegrity();
      setIsValid(verifyRes.valid);
      setCorruptedIndex(verifyRes.corrupted_index);
      const recordsRes = await fetchAuditRecords();
      setRecords(recordsRes.records);
    } catch (err: any) {
      console.error('Failed to simulate tampering:', err);
      setError('Tamper simulation error occurred.');
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleRestoreLedger = async () => {
    setIsActionLoading(true);
    setError(null);
    try {
      await resetAuditChain();
      const [verifyRes, recordsRes] = await Promise.all([
        verifyAuditIntegrity(),
        fetchAuditRecords(),
      ]);
      setIsValid(verifyRes.valid);
      setCorruptedIndex(verifyRes.corrupted_index);
      setRootHash(recordsRes.root_hash);
      setRecords(recordsRes.records);
      setError(null);
    } catch (err: any) {
      console.error('Failed to restore audit chain:', err);
      setError('Failed to restore ledger integrity.');
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleDownloadPdf = () => {
    const link = document.createElement('a');
    link.href = getReportDownloadUrl();
    link.download = 'bitguard_incident_report.pdf';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // API Mode Action: Create Manual Object-Lock Anchor
  const handleCreateAnchor = async () => {
    setIsActionLoading(true);
    setActionNotice(null);
    try {
      const res = await triggerManualAnchor();
      setLastAnchorStatus('ANCHORED');
      if (res.anchor?.ts) {
        setLastAnchorTime(
          new Date(res.anchor.ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
        );
      }
      if (res.anchor?.storage_uri) {
        setLastAnchorUri(res.anchor.storage_uri);
      }
      setActionNotice({
        type: 'success',
        text: `External WORM object-lock anchor successfully created: ${res.anchor?.storage_uri || 's3://bitguard-audit-worm'}`,
      });
      await loadAuditData();
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err.message || 'Failed to create object-lock anchor.' });
    } finally {
      setIsActionLoading(false);
    }
  };

  // API Mode Exports (Milestone S35 / F20)
  const handleExportIncident = async (format: 'pdf' | 'csv') => {
    const targetId = selectedIncidentId || (incidents[0]?.id ?? 'inc-7702-drain-01');
    setExportingType(`incident-${format}`);
    setActionNotice(null);
    try {
      await exportIncidentReport(targetId, format);
      setActionNotice({
        type: 'success',
        text: `Incident post-mortem report (${format.toUpperCase()}) for '${targetId}' downloaded.`,
      });
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err.message || `Failed to export incident post-mortem ${format}.` });
    } finally {
      setExportingType(null);
    }
  };

  const handleExportMonthly = async (format: 'pdf' | 'csv') => {
    setExportingType(`monthly-${format}`);
    setActionNotice(null);
    try {
      await exportMonthlyReport(reportYear, reportMonth, format);
      setActionNotice({
        type: 'success',
        text: `Monthly control report (${format.toUpperCase()}) for ${reportYear}-${String(reportMonth).padStart(2, '0')} downloaded.`,
      });
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err.message || `Failed to export monthly control report ${format}.` });
    } finally {
      setExportingType(null);
    }
  };

  const handleExportPolicyHistory = async (format: 'pdf' | 'csv') => {
    setExportingType(`policy-${format}`);
    setActionNotice(null);
    try {
      await exportPolicyHistoryReport(format, policyVersionFilter || undefined);
      setActionNotice({
        type: 'success',
        text: `Policy change and dual-control approval history (${format.toUpperCase()}) downloaded.`,
      });
    } catch (err: any) {
      setActionNotice({ type: 'error', text: err.message || `Failed to export policy change history ${format}.` });
    } finally {
      setExportingType(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl backdrop-blur">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center space-x-3.5">
            <div className="p-2.5 bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 rounded-lg border border-emerald-500/30 text-emerald-400">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
                Cryptographic Audit Ledger & Compliance Reports
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-800/50 text-emerald-300 font-mono">
                  SHA-256 Chained
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/50 text-cyan-300 font-mono uppercase">
                  {isApiMode ? 'DATA: REAL' : 'DATA: SYNTHETIC'}
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Append-only tamper-evident hash chain logging every signing decision. BitGuard reduces and contains unauthorized transaction signing with verified audit non-repudiation (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection). Operating performance target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per docs/PERF.md). Production-ready architecture; pilot after audit and shadow-mode validation.
              </p>
            </div>
          </div>

          {/* Top Actions */}
          <div className="flex items-center gap-3">
            {!isApiMode ? (
              <button
                onClick={handleDownloadPdf}
                className="flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
              >
                <FileDown className="w-4 h-4" />
                <span>Download Post-Mortem PDF</span>
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleExportMonthly('pdf')}
                  disabled={exportingType !== null}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-md transition-all cursor-pointer disabled:opacity-50"
                  title="Export monthly control report stamped with audit chain state"
                >
                  <FileDown className="w-3.5 h-3.5" />
                  <span>Monthly Report (PDF)</span>
                </button>
                <button
                  onClick={() => handleExportMonthly('csv')}
                  disabled={exportingType !== null}
                  className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs transition-all cursor-pointer disabled:opacity-50"
                  title="Export monthly control metrics CSV"
                >
                  <span>CSV</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Defensive Boundary & Architectural Limits Note linking to docs/LIMITS.md */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 text-xs text-slate-400 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-lg">
        <div className="flex items-start space-x-2.5">
          <AlertCircle className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
          <div>
            <span className="font-bold text-slate-200">System Boundaries & Compensating Controls: </span>
            <span>
              BitGuard reduces and contains blast radius from compromised credentials or rogue callers; a limit-aware attacker can still move value up to configured velocity caps. Defense-in-depth requires paired compensating controls for Cloud HSM root access, compromised approver laptops, low-and-slow velocity evasion, and bytecode decoder gaps. Review the comprehensive limitation matrix in{' '}
              <a
                href="/docs/LIMITS.md"
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:text-cyan-300 underline font-mono font-semibold"
              >
                docs/LIMITS.md
              </a>.
            </span>
          </div>
        </div>
        <a
          href="/docs/LIMITS.md"
          target="_blank"
          rel="noopener noreferrer"
          className="shrink-0 flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 font-semibold text-xs transition-all cursor-pointer"
        >
          <FileText className="w-3.5 h-3.5" />
          <span>docs/LIMITS.md</span>
        </a>
      </div>

      {actionNotice && (
        <div
          className={cn(
            'p-4 rounded-xl border text-xs flex items-center justify-between space-x-2',
            actionNotice.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          )}
        >
          <div className="flex items-center space-x-2">
            {actionNotice.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            )}
            <span>{actionNotice.text}</span>
          </div>
          <button
            onClick={() => setActionNotice(null)}
            className="text-slate-400 hover:text-white text-xs font-mono"
          >
            ✕
          </button>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-center space-x-2 text-xs">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit Integrity Status & Anchor Metadata Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Card 1: Chain Integrity Shield */}
        <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center space-x-2">
                <Hash className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white tracking-wide">
                  Audit Chain Integrity & Cryptographic Seal
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                {isApiMode
                  ? 'Continuous background verification against WORM object-lock storage: SHA-256(prev_hash : ts : actor : payload).'
                  : "Each block is hashed with its previous block's digest: SHA-256(prev_hash : ts : req_id : action : risk : rules)."}
              </p>
            </div>

            {/* Dynamic Status Badge */}
            <div>
              {isValid ? (
                <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-bold shadow-lg shadow-emerald-950/50">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>INTEGRITY VERIFIED</span>
                </div>
              ) : (
                <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-rose-500/20 border border-rose-500/50 text-rose-300 text-xs font-bold shadow-lg shadow-rose-950/60 animate-pulse">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>
                    {isApiMode && firstBadSeq !== null
                      ? `CHAIN COMPROMISED AT RECORD #${firstBadSeq} — SHA-256 MISMATCH`
                      : `CHAIN COMPROMISED AT RECORD #${corruptedIndex ?? 'UNKNOWN'} — SHA-256 MISMATCH`}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Root Hash & Specs Grid */}
          <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">
                  Ledger Head / Root Hash (SHA-256)
                </span>
                <span className="text-[9px] px-1.5 py-0.2 rounded border uppercase font-mono font-bold bg-cyan-500/20 text-cyan-300 border-cyan-500/40">
                  {isApiMode ? 'REAL' : 'SYNTHETIC'}
                </span>
              </div>
              <span className="text-xs text-cyan-300 break-all select-all font-semibold">
                {rootHash || '0'.repeat(64)}
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono flex items-center justify-between">
              <div>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block">
                    Chained Audit Blocks
                  </span>
                  <span className="text-[9px] px-1.5 py-0.2 rounded border uppercase font-mono font-bold bg-cyan-500/20 text-cyan-300 border-cyan-500/40">
                    {isApiMode ? 'REAL' : 'SYNTHETIC'}
                  </span>
                </div>
                <span className="text-lg text-white font-bold">
                  {apiAuditVerify?.checked_entries ?? records.length}{' '}
                  <span className="text-xs text-slate-400 font-normal">Entries Checked</span>
                </span>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">
                  Genesis Vector
                </span>
                <span className="text-xs text-emerald-400 font-semibold">0x000...000 (64)</span>
              </div>
            </div>
          </div>

          {/* Milestone U9 Requirement: Last Anchor Time and Status */}
          {isApiMode && (
            <div className="mt-4 pt-4 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                <div className="flex items-center space-x-1.5 text-[10px] text-slate-500 uppercase tracking-wider mb-1 font-mono">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Last Anchor Time</span>
                </div>
                <div className="text-xs font-mono font-semibold text-slate-200">
                  {lastAnchorTime || 'No checkpoint recorded'}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                <div className="flex items-center space-x-1.5 text-[10px] text-slate-500 uppercase tracking-wider mb-1 font-mono">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Anchor Status</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span
                    className={cn(
                      'text-xs font-mono font-bold px-2 py-0.5 rounded border',
                      lastAnchorStatus === 'ANCHORED'
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                    )}
                  >
                    {lastAnchorStatus}
                  </span>
                  {lastAnchorUri && (
                    <span className="text-[10px] text-slate-400 font-mono truncate" title={lastAnchorUri}>
                      {lastAnchorUri.replace('s3://', '')}
                    </span>
                  )}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-mono">
                    WORM Checkpoint
                  </span>
                  <span className="text-[11px] text-slate-300">Immutable object lock</span>
                </div>
                <button
                  onClick={handleCreateAnchor}
                  disabled={isActionLoading}
                  className="px-2.5 py-1.5 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-[11px] font-bold transition-all cursor-pointer disabled:opacity-50"
                >
                  Create Anchor
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Card 2: Right Column — Live Tamper in Demo, or Quick Post-Mortem in API Mode */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl flex flex-col justify-between">
          {!isApiMode ? (
            <>
              <div>
                <div className="flex items-center space-x-2 pb-3 mb-3 border-b border-slate-800">
                  <Flame className="w-4 h-4 text-amber-400" />
                  <h3 className="text-sm font-bold text-white tracking-wide">
                    Live Tamper Simulation
                  </h3>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  Demonstrate forensic resilience: corrupt a historical database record payload (e.g. mutate a{' '}
                  <code className="text-rose-400">deny</code> decision into <code className="text-emerald-400">allow</code>) and verify that the cryptographic validator immediately detects the exact block mismatch.
                </p>
              </div>

              <div className="space-y-3 pt-2">
                <button
                  onClick={handleSimulateTamper}
                  disabled={isActionLoading || !isValid}
                  className={cn(
                    'w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg text-xs font-bold transition-all border cursor-pointer',
                    isValid
                      ? 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-sm'
                      : 'bg-slate-800 text-slate-500 border-slate-700 cursor-not-allowed opacity-60'
                  )}
                >
                  <Flame className="w-4 h-4 text-rose-400" />
                  <span>Simulate DB Tampering</span>
                </button>

                <button
                  onClick={handleRestoreLedger}
                  disabled={isActionLoading || isValid}
                  className={cn(
                    'w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg text-xs font-bold transition-all border cursor-pointer',
                    !isValid
                      ? 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border-emerald-500/50 shadow-lg shadow-emerald-950/60'
                      : 'bg-slate-800 text-slate-500 border-slate-700 cursor-not-allowed opacity-60'
                  )}
                >
                  <RefreshCw className={cn('w-4 h-4 text-emerald-400', isActionLoading && 'animate-spin')} />
                  <span>Restore Ledger Integrity</span>
                </button>
              </div>
            </>
          ) : (
            <>
              <div>
                <div className="flex items-center space-x-2 pb-3 mb-3 border-b border-slate-800">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-white tracking-wide">
                    S35 Compliance Exporter
                  </h3>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed mb-3">
                  Export tamper-evident reports with audit-chain verification stamps and explicit data labels (REAL) for SOC 2 and ISO 27001 auditor packages.
                </p>

                <div className="space-y-3 pt-1">
                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                      Incident Post-Mortem Target
                    </label>
                    <select
                      value={selectedIncidentId}
                      onChange={(e) => setSelectedIncidentId(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
                    >
                      {incidents.map((inc) => (
                        <option key={inc.id} value={inc.id}>
                          {inc.id} — {inc.trigger} ({inc.time_to_contain_ms != null ? `${inc.time_to_contain_ms.toFixed(1)}ms` : inc.status})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleExportIncident('pdf')}
                      disabled={exportingType !== null}
                      className="flex-1 flex items-center justify-center space-x-1 py-2 px-3 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold transition-all cursor-pointer disabled:opacity-50"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Post-Mortem PDF</span>
                    </button>
                    <button
                      onClick={() => handleExportIncident('csv')}
                      disabled={exportingType !== null}
                      className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-bold transition-all cursor-pointer disabled:opacity-50"
                    >
                      CSV
                    </button>
                  </div>
                </div>
              </div>

              {/* Monthly Control Report Export */}
              <div className="pt-4 border-t border-slate-800/80">
                <div className="flex items-center justify-between text-[11px] text-slate-400 mb-2">
                  <div className="flex items-center space-x-1.5">
                    <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Monthly Control Report:</span>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    <input
                      type="number"
                      min={2020}
                      max={2030}
                      value={reportYear}
                      onChange={(e) => setReportYear(Number(e.target.value))}
                      className="w-16 bg-slate-950 border border-slate-800 rounded px-1.5 py-0.5 text-xs text-slate-200 font-mono text-center focus:border-cyan-500 outline-none"
                    />
                    <select
                      value={reportMonth}
                      onChange={(e) => setReportMonth(Number(e.target.value))}
                      className="bg-slate-950 border border-slate-800 rounded px-1.5 py-0.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
                    >
                      {Array.from({ length: 12 }, (_, i) => i + 1).map((m) => (
                        <option key={m} value={m}>
                          {String(m).padStart(2, '0')}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleExportMonthly('pdf')}
                    disabled={exportingType !== null}
                    className="flex-1 py-1.5 px-2.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold transition-all cursor-pointer disabled:opacity-50"
                  >
                    Monthly Report (PDF)
                  </button>
                  <button
                    onClick={() => handleExportMonthly('csv')}
                    disabled={exportingType !== null}
                    className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-bold transition-all cursor-pointer disabled:opacity-50"
                  >
                    CSV
                  </button>
                </div>
              </div>

              {/* Policy Change History Export */}
              <div className="pt-4 border-t border-slate-800/80">
                <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1.5">
                  <span>Policy Change History:</span>
                  <span className="font-mono text-emerald-400 text-[10px]">Ed25519 Signed</span>
                </div>
                <div className="mb-2">
                  <input
                    type="text"
                    placeholder="Filter version e.g. 1.0.0 (optional)"
                    value={policyVersionFilter}
                    onChange={(e) => setPolicyVersionFilter(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 font-mono placeholder:text-slate-600 focus:border-cyan-500 outline-none"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleExportPolicyHistory('pdf')}
                    disabled={exportingType !== null}
                    className="flex-1 py-1.5 px-2.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold transition-all cursor-pointer disabled:opacity-50"
                  >
                    Change History (PDF)
                  </button>
                  <button
                    onClick={() => handleExportPolicyHistory('csv')}
                    disabled={exportingType !== null}
                    className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-bold transition-all cursor-pointer disabled:opacity-50"
                  >
                    CSV
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Milestone U9 Requirement: List incidents with time_to_contain and an expandable timeline */}
      {isApiMode && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <h4 className="text-xs font-bold font-mono uppercase text-slate-300">
                Security Incidents & Automated Containment (Milestone S19 / F14)
              </h4>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] font-mono text-slate-500">
                {incidents.length} Incident Record(s) Logged
              </span>
              <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border border-cyan-500/40 bg-cyan-500/20 text-cyan-300 uppercase">
                {isApiMode ? 'REAL' : 'SYNTHETIC'}
              </span>
            </div>
          </div>

          <div className="divide-y divide-slate-800/80">
            {incidents.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-xs">
                No security incidents currently active or contained.
              </div>
            ) : (
              incidents.map((inc) => {
                const isExpanded = expandedIncidentId === inc.id;
                return (
                  <div key={inc.id} className="p-4 hover:bg-slate-800/20 transition-colors">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2.5">
                          <span className="font-mono font-bold text-xs text-white">{inc.id}</span>
                          <span
                            className={cn(
                              'px-2 py-0.5 rounded text-[10px] font-bold uppercase border',
                              inc.status === 'CONTAINED' && 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
                              inc.status === 'OPEN' && 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse',
                              inc.status === 'RESOLVED' && 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
                              inc.status === 'ESCALATED' && 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            )}
                          >
                            {inc.status}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/50 text-[10px] font-bold">
                            {inc.severity}
                          </span>
                          <span className="text-xs text-slate-400 font-mono">{inc.trigger}</span>
                        </div>
                        <div className="flex items-center space-x-4 text-[11px] text-slate-400">
                          <span>
                            Detected: <strong className="text-slate-300 font-mono">{new Date(inc.detected_at).toISOString().replace('T', ' ').slice(0, 19)} UTC</strong>
                          </span>
                          {inc.contained_at && (
                            <span>
                              Contained: <strong className="text-slate-300 font-mono">{new Date(inc.contained_at).toISOString().replace('T', ' ').slice(0, 19)} UTC</strong>
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Containment Latency & Action Buttons */}
                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <div className="flex items-center justify-end gap-1 mb-0.5">
                            <span className="text-[10px] uppercase font-mono text-slate-500 block">
                              Time to Contain
                            </span>
                            <span className="px-1 py-0.2 rounded text-[8px] font-mono font-bold border border-emerald-500/40 bg-emerald-500/20 text-emerald-300 uppercase">
                              REAL
                            </span>
                          </div>
                          <span className="text-xs font-mono font-bold text-emerald-400">
                            {inc.time_to_contain_ms != null ? `${inc.time_to_contain_ms.toFixed(1)} ms` : 'N/A'}
                          </span>
                        </div>

                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => exportIncidentReport(inc.id, 'pdf')}
                            className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-bold transition-all cursor-pointer"
                            title="Export Post-Mortem PDF"
                          >
                            PDF
                          </button>
                          <button
                            onClick={() => exportIncidentReport(inc.id, 'csv')}
                            className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-bold transition-all cursor-pointer"
                            title="Export Post-Mortem CSV"
                          >
                            CSV
                          </button>
                          <button
                            onClick={() => setExpandedIncidentId(isExpanded ? null : inc.id)}
                            className="flex items-center space-x-1 px-3 py-1.5 rounded bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 text-[11px] font-bold transition-all cursor-pointer"
                          >
                            <span>{isExpanded ? 'Hide' : 'Timeline'}</span>
                            {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Expandable Timeline Component */}
                    {isExpanded && (
                      <div className="mt-4 pt-4 border-t border-slate-800/80 bg-slate-950/60 rounded-lg p-4">
                        <div className="flex items-center space-x-2 mb-3">
                          <History className="w-4 h-4 text-cyan-400" />
                          <h5 className="text-xs font-bold font-mono uppercase text-slate-300">
                            Incident Containment Timeline ({inc.timeline?.length || 0} Milestones)
                          </h5>
                        </div>

                        {(!inc.timeline || inc.timeline.length === 0) ? (
                          <p className="text-xs text-slate-500 italic">No timeline events recorded.</p>
                        ) : (
                          <div className="space-y-2.5 border-l-2 border-slate-800 ml-2 pl-4">
                            {inc.timeline.map((evt, idx) => (
                              <div key={evt.id || idx} className="relative group">
                                <div className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-cyan-400 border-2 border-slate-950" />
                                <div className="flex items-center space-x-2 text-[10px] font-mono text-slate-500">
                                  <span>{new Date(evt.timestamp).toISOString().replace('T', ' ').slice(0, 19)} UTC</span>
                                  <span className="px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 border border-slate-700 uppercase">
                                    {evt.event_type}
                                  </span>
                                </div>
                                <p className="text-xs text-slate-200 mt-0.5">{evt.message}</p>
                                {evt.details && Object.keys(evt.details).length > 0 && (
                                  <div className="mt-1 text-[11px] font-mono text-slate-400 bg-slate-900/60 rounded px-2 py-1 border border-slate-800/60 inline-block">
                                    {Object.entries(evt.details)
                                      .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
                                      .join('  •  ')}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Audit Chain Ledger Records Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-bold font-mono uppercase text-slate-300">
              Audit Chain Immutable Record Log
            </h4>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            {records.length} Chained Blocks
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-2.5 font-semibold">BLOCK #</th>
                <th className="px-4 py-2.5 font-semibold">TIMESTAMP</th>
                <th className="px-4 py-2.5 font-semibold">REQUEST ID</th>
                <th className="px-4 py-2.5 font-semibold">ACTION</th>
                <th className="px-4 py-2.5 font-semibold">RISK</th>
                <th className="px-4 py-2.5 font-semibold">PRIMARY RULES</th>
                <th className="px-4 py-2.5 font-semibold">PREVIOUS HASH</th>
                <th className="px-4 py-2.5 font-semibold">BLOCK HASH</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
                    <span>Loading cryptographic audit records...</span>
                  </td>
                </tr>
              ) : records.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                    No audit records logged yet.
                  </td>
                </tr>
              ) : (
                records.map((entry) => {
                  const isCorrupted =
                    (!isApiMode && corruptedIndex === entry.index) ||
                    (isApiMode && firstBadSeq !== null && entry.index >= firstBadSeq);
                  return (
                    <tr
                      key={entry.index}
                      className={cn(
                        'hover:bg-slate-800/40 transition-colors',
                        isCorrupted && 'bg-rose-500/15 font-bold border-l-4 border-rose-500'
                      )}
                    >
                      <td className="px-4 py-2.5 text-slate-300">
                        #{entry.index}
                        {isCorrupted && (
                          <span className="ml-1.5 text-[9px] px-1 py-0.2 rounded bg-rose-500/30 text-rose-300 border border-rose-500">
                            TAMPERED
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-slate-400">
                        {new Date(entry.timestamp * 1000).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="px-4 py-2.5 text-slate-200">
                        {entry.request_id}
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold border uppercase',
                            entry.action === 'allow' && 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
                            entry.action === 'hold' && 'bg-amber-500/20 text-amber-300 border-amber-500/40',
                            entry.action === 'deny' && 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          )}
                        >
                          {entry.action}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-bold">
                        <span
                          className={cn(
                            entry.risk >= 80 ? 'text-rose-400' : entry.risk >= 40 ? 'text-amber-400' : 'text-emerald-400'
                          )}
                        >
                          {entry.risk}/100
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-slate-300">
                        {entry.rule_hits.length > 0 ? (
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                            {entry.rule_hits.slice(0, 2).join(', ')}
                          </span>
                        ) : (
                          <span className="text-slate-500 text-[10px]">—</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-slate-500 text-[11px]" title={entry.prev_hash}>
                        {entry.prev_hash.slice(0, 8)}...{entry.prev_hash.slice(-6)}
                      </td>
                      <td className="px-4 py-2.5 text-cyan-400 text-[11px] font-semibold" title={entry.entry_hash}>
                        {entry.entry_hash.slice(0, 8)}...{entry.entry_hash.slice(-6)}
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
