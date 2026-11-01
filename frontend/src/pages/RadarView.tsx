import React, { useState, useEffect } from 'react';
import {
  Radar,
  RefreshCw,
  Info,
  ExternalLink,
  Search,
  Filter,
  AlertCircle,
} from 'lucide-react';
import { fetchRadar, RadarScanResult, Type4Finding } from '../api';
import { truncateAddress, cn } from '../utils';

export const RadarView: React.FC = () => {
  const [radarResult, setRadarResult] = useState<RadarScanResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [useLiveRpc, setUseLiveRpc] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterSuspiciousOnly, setFilterSuspiciousOnly] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const loadRadar = async (forceCached: boolean = false) => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchRadar({ n_blocks: 5, force_cached: forceCached });
      setRadarResult(data);
    } catch (err: any) {
      console.warn('Live radar error, falling back to cached sample:', err);
      try {
        const cached = await fetchRadar({ n_blocks: 5, force_cached: true });
        setRadarResult(cached);
      } catch (fallbackErr: any) {
        setError('Failed to load radar scan data.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadRadar(!useLiveRpc);
  }, [useLiveRpc]);

  const findings: Type4Finding[] = radarResult?.findings ?? [];

  const filteredFindings = findings.filter((f) => {
    if (filterSuspiciousOnly && !f.is_suspicious) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchHash = f.tx_hash.toLowerCase().includes(q);
      const matchDelegate = (f.delegate_address || '').toLowerCase().includes(q);
      const matchFrom = (f.from_address || '').toLowerCase().includes(q);
      const matchBlock = f.block_number.toString().includes(q);
      const matchPattern = f.patterns.some((p) => p.toLowerCase().includes(q));
      return matchHash || matchDelegate || matchFrom || matchBlock || matchPattern;
    }
    return true;
  });

  const getRiskBadge = (score: number) => {
    if (score >= 70) {
      return {
        bg: 'bg-rose-500/20 text-rose-300 border-rose-500/50',
        label: `CRITICAL (${score})`,
      };
    }
    if (score >= 40) {
      return {
        bg: 'bg-amber-500/20 text-amber-300 border-amber-500/50',
        label: `SUSPICIOUS (${score})`,
      };
    }
    return {
      bg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
      label: `BENIGN (${score})`,
    };
  };

  const getSourceBadge = (source?: string) => {
    if (source === 'live_rpc') {
      return {
        label: 'LIVE ETHEREUM RPC',
        style: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-sm',
        indicator: 'bg-cyan-400 animate-pulse',
      };
    }
    return {
      label: 'OFFLINE CACHED SAMPLE',
      style: 'bg-slate-800 text-slate-300 border-slate-700',
      indicator: 'bg-amber-400',
    };
  };

  const currentSource = getSourceBadge(radarResult?.source);

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl backdrop-blur">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center space-x-3.5">
            <div className="p-2.5 bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 rounded-lg border border-cyan-500/30 text-cyan-400">
              <Radar className="w-6 h-6 animate-spin-slow" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-wide">
                  EIP-7702 Set-Code Radar
                </h2>
                <div className={cn('flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-[10px] font-bold tracking-wider font-mono', currentSource.style)}>
                  <span className={cn('w-1.5 h-1.5 rounded-full', currentSource.indicator)} />
                  <span>{currentSource.label}</span>
                </div>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Live mainnet block scanner inspecting Type-4 transactions for batch nonce spraying, single-delegate sweeps, and unauthorized authority delegations.
              </p>
            </div>
          </div>

          {/* Actions & Live/Mock Toggle */}
          <div className="flex items-center space-x-3">
            {/* Live / Offline Toggle Button */}
            <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800">
              <button
                onClick={() => setUseLiveRpc(true)}
                className={cn(
                  'px-3 py-1 text-xs font-semibold rounded transition-all cursor-pointer',
                  useLiveRpc
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-white'
                )}
              >
                Live RPC
              </button>
              <button
                onClick={() => setUseLiveRpc(false)}
                className={cn(
                  'px-3 py-1 text-xs font-semibold rounded transition-all cursor-pointer',
                  !useLiveRpc
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-white'
                )}
              >
                Offline Sample
              </button>
            </div>

            {/* Refresh Button */}
            <button
              onClick={() => loadRadar(!useLiveRpc)}
              disabled={isLoading}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw className={cn('w-3.5 h-3.5', isLoading && 'animate-spin')} />
              <span>{isLoading ? 'Scanning Blocks...' : 'Scan Now'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-center space-x-2 text-xs">
            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Mandatory Disclosure / Disclaimer Alert */}
        <div className="mt-4 p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-start space-x-2.5 text-xs text-slate-300">
          <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong className="text-white">Pattern match heuristic disclosure:</strong> This radar scans public Type-4 transactions on Ethereum for high-risk exploit patterns (consecutive nonce batching, high authorization velocity, single-delegate sweeping). It does not accuse legitimate smart-account upgrades without exchange internal signer context.
          </p>
        </div>
      </div>

      {/* Telemetry Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <span className="text-xs text-slate-400 font-mono uppercase block">Latest Block</span>
          <span className="text-2xl font-bold font-mono text-cyan-400 mt-1 block">
            {radarResult ? `#${radarResult.latest_block.toLocaleString()}` : '—'}
          </span>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <span className="text-xs text-slate-400 font-mono uppercase block">Type-4 Txs Discovered</span>
          <span className="text-2xl font-bold font-mono text-white mt-1 block">
            {radarResult?.findings_count ?? 0}
          </span>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-rose-950/60">
          <span className="text-xs text-rose-400 font-mono uppercase block">Anomalies Detected</span>
          <span className="text-2xl font-bold font-mono text-rose-400 mt-1 block">
            {radarResult?.suspicious_count ?? 0}
          </span>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <span className="text-xs text-slate-400 font-mono uppercase block">Blocks Analyzed</span>
          <span className="text-2xl font-bold font-mono text-slate-200 mt-1 block">
            {radarResult?.blocks_scanned ?? 5} Blocks
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-semibold text-slate-400 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" />
            Filter:
          </span>
          <button
            onClick={() => setFilterSuspiciousOnly(false)}
            className={cn(
              'px-2.5 py-1 text-xs font-medium rounded transition-all cursor-pointer',
              !filterSuspiciousOnly
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-white'
            )}
          >
            All Findings ({findings.length})
          </button>
          <button
            onClick={() => setFilterSuspiciousOnly(true)}
            className={cn(
              'px-2.5 py-1 text-xs font-medium rounded transition-all cursor-pointer',
              filterSuspiciousOnly
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'text-slate-400 hover:text-white'
            )}
          >
            Suspicious Patterns Only ({radarResult?.suspicious_count ?? 0})
          </button>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search hash, delegate, pattern, block..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 font-semibold">BLOCK</th>
                <th className="px-4 py-3 font-semibold">TX HASH</th>
                <th className="px-4 py-3 font-semibold">DELEGATE CONTRACT</th>
                <th className="px-4 py-3 font-semibold text-center">AUTHS</th>
                <th className="px-4 py-3 font-semibold text-center">CONSECUTIVE NONCES</th>
                <th className="px-4 py-3 font-semibold text-center">RISK SCORE</th>
                <th className="px-4 py-3 font-semibold">DETECTED HEURISTIC PATTERNS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                    {isLoading ? 'Scanning recent blocks...' : 'No transactions match the selected filter.'}
                  </td>
                </tr>
              ) : (
                filteredFindings.map((f) => {
                  const riskBadge = getRiskBadge(f.risk_score);

                  return (
                    <tr
                      key={f.tx_hash}
                      className={cn(
                        'hover:bg-slate-800/40 transition-colors',
                        f.is_suspicious ? 'bg-rose-950/10' : 'bg-transparent'
                      )}
                    >
                      {/* Block Number */}
                      <td className="px-4 py-3 font-bold text-cyan-400">
                        #{f.block_number}
                      </td>

                      {/* Tx Hash */}
                      <td className="px-4 py-3 font-bold text-slate-200" title={f.tx_hash}>
                        <div className="flex items-center space-x-1.5">
                          <span>{truncateAddress(f.tx_hash)}</span>
                          <a
                            href={`https://etherscan.io/tx/${f.tx_hash}`}
                            target="_blank"
                            rel="noreferrer"
                            className="text-slate-500 hover:text-cyan-400"
                          >
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      </td>

                      {/* Delegate Address */}
                      <td className="px-4 py-3 text-slate-300 font-mono" title={f.delegate_address || 'None'}>
                        {truncateAddress(f.delegate_address)}
                      </td>

                      {/* Auth Count */}
                      <td className="px-4 py-3 text-center font-bold text-slate-200">
                        {f.auth_count}
                      </td>

                      {/* Consecutive Nonces Flag */}
                      <td className="px-4 py-3 text-center">
                        {f.has_consecutive_nonces ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                            FLAGGED ({f.max_consecutive_nonces})
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 border border-slate-700">
                            NO ({f.max_consecutive_nonces})
                          </span>
                        )}
                      </td>

                      {/* Risk Score */}
                      <td className="px-4 py-3 text-center">
                        <span className={cn('px-2.5 py-0.5 rounded-full text-[10px] font-bold border', riskBadge.bg)}>
                          {riskBadge.label}
                        </span>
                      </td>

                      {/* Pattern Badges */}
                      <td className="px-4 py-3">
                        {f.patterns.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {f.patterns.map((p) => (
                              <span
                                key={p}
                                className={cn(
                                  'px-2 py-0.5 rounded text-[10px] border font-sans',
                                  p === 'consecutive_nonces_spray'
                                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                    : p === 'high_volume_authorizations'
                                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                                    : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                                )}
                              >
                                {p.replace(/_/g, ' ')}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
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
