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
} from 'lucide-react';
import {
  fetchAuditRecords,
  verifyAuditIntegrity,
  simulateAuditTamper,
  resetAuditChain,
  getReportDownloadUrl,
  AuditRecord,
} from '../api';
import { cn } from '../utils';

export const ReportsView: React.FC = () => {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [rootHash, setRootHash] = useState<string>('');
  const [isValid, setIsValid] = useState<boolean>(true);
  const [corruptedIndex, setCorruptedIndex] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isActionLoading, setIsActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const loadAuditData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [recordsRes, verifyRes] = await Promise.all([
        fetchAuditRecords(),
        verifyAuditIntegrity(),
      ]);
      setRecords(recordsRes.records);
      setRootHash(recordsRes.root_hash);
      setIsValid(verifyRes.valid);
      setCorruptedIndex(verifyRes.corrupted_index);
    } catch (err: any) {
      console.error('Error fetching audit records:', err);
      setError('Failed to fetch cryptographic audit ledger from backend.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAuditData();
  }, []);

  const handleSimulateTamper = async () => {
    setIsActionLoading(true);
    try {
      await simulateAuditTamper();
      const verifyRes = await verifyAuditIntegrity();
      setIsValid(verifyRes.valid);
      setCorruptedIndex(verifyRes.corrupted_index);
      // Refresh record view to reflect tampered entry
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
      // 1. Call POST /api/audit/reset
      await resetAuditChain();

      // 2. Await response and immediately re-fetch verify and records
      const [verifyRes, recordsRes] = await Promise.all([
        verifyAuditIntegrity(),
        fetchAuditRecords(),
      ]);

      // 3. Update the UI state: clear error banners, set valid, and flip to green INTEGRITY VERIFIED
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
                Cryptographic Audit Ledger & Post-Mortem Generator
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-800/50 text-emerald-300 font-mono">
                  SHA-256 Chained
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Append-only tamper-evident merkle chain logging every autonomous firewall evaluation for non-repudiation and forensic post-mortems.
              </p>
            </div>
          </div>

          {/* Top Actions: Download PDF */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleDownloadPdf}
              className="flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
            >
              <FileDown className="w-4 h-4" />
              <span>Download Post-Mortem PDF</span>
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-center space-x-2 text-xs">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit Integrity Status & Tamper Simulator Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Card 1: Chain Integrity Shield */}
        <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center space-x-2">
                <Hash className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white tracking-wide">
                  Ledger State & Cryptographic Seal
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Each block is hashed with its previous block's digest: <code className="text-slate-300">SHA-256(prev_hash : ts : req_id : action : risk : rules)</code>
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
                  <span>CHAIN COMPROMISED AT RECORD #{corruptedIndex} — SHA-256 MISMATCH</span>
                </div>
              )}
            </div>
          </div>

          {/* Root Hash & Specs */}
          <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">
                Ledger Head / Root Hash (SHA-256)
              </span>
              <span className="text-xs text-cyan-300 break-all select-all font-semibold">
                {rootHash || '0'.repeat(64)}
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono flex items-center justify-between">
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">
                  Chained Audit Blocks
                </span>
                <span className="text-lg text-white font-bold">
                  {records.length} <span className="text-xs text-slate-400 font-normal">Entries</span>
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
        </div>

        {/* Card 2: Live Tamper Testing Lab */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center space-x-2 pb-3 mb-3 border-b border-slate-800">
              <Flame className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-bold text-white tracking-wide">
                Live Tamper Simulation
              </h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              Demonstrate forensic resilience: corrupt a historical database record payload (e.g. mutate a <code className="text-rose-400">deny</code> decision into <code className="text-emerald-400">allow</code>) and verify that the cryptographic validator immediately detects the exact block mismatch.
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
        </div>
      </div>

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
                  const isCorrupted = corruptedIndex === entry.index;
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
