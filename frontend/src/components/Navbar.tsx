import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Activity, RefreshCw } from 'lucide-react';
import { cn } from '../utils';

export type DashboardTab = 'replay' | 'feed' | 'radar' | 'lab' | 'reports' | 'approvals';

interface NavbarProps {
  currentTab: DashboardTab;
  onSelectTab: (tab: DashboardTab) => void;
  breakerState: 'Normal' | 'Elevated' | 'Hold' | 'Lockdown' | string;
  onReset: () => void;
  isResetting?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onSelectTab,
  breakerState,
  onReset,
  isResetting,
}) => {
  const getBreakerBadge = (state: string) => {
    switch (state) {
      case 'Normal':
        return {
          icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
          label: 'NORMAL OPERATION',
          bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
          dot: 'bg-emerald-400',
        };
      case 'Elevated':
        return {
          icon: <Activity className="w-4 h-4 text-amber-400 animate-pulse" />,
          label: 'ELEVATED SCRUTINY',
          bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
          dot: 'bg-amber-400',
        };
      case 'Hold':
        return {
          icon: <ShieldAlert className="w-4 h-4 text-amber-500" />,
          label: 'MANUAL HOLD ACTIVE',
          bg: 'bg-amber-500/15 border-amber-500/40 text-amber-300',
          dot: 'bg-amber-500',
        };
      case 'Lockdown':
      default:
        return {
          icon: <ShieldAlert className="w-4 h-4 text-rose-400 animate-bounce" />,
          label: 'BREAKER LOCKDOWN',
          bg: 'bg-rose-500/20 border-rose-500/50 text-rose-300 shadow-lg shadow-rose-900/30',
          dot: 'bg-rose-500 animate-ping',
        };
    }
  };

  const badge = getBreakerBadge(breakerState);

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand & Badges */}
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <div className="p-2 bg-gradient-to-br from-cyan-500/20 to-blue-600/30 rounded-lg border border-cyan-500/30">
                <Shield className="w-6 h-6 text-cyan-400" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
                    BitGuard
                    <span className="text-slate-400 text-xs font-normal">| Hot Wallet Signing Firewall</span>
                  </h1>
                </div>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-[10px] font-medium tracking-wide uppercase px-1.5 py-0.5 rounded bg-blue-950/60 text-blue-300 border border-blue-800/40">
                    DEFENSIVE SIMULATION
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="hidden md:flex items-center space-x-1 bg-slate-900/90 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => onSelectTab('replay')}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer',
                currentTab === 'replay'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              )}
            >
              Incident Replay
            </button>
            <button
              onClick={() => onSelectTab('feed')}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer',
                currentTab === 'feed'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              )}
            >
              Live Feed
            </button>
            <button
              onClick={() => onSelectTab('radar')}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer',
                currentTab === 'radar'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              )}
            >
              7702 Radar
            </button>
            <button
              onClick={() => onSelectTab('lab')}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer',
                currentTab === 'lab'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              )}
            >
              Sensitivity Lab
            </button>
            <button
              onClick={() => onSelectTab('reports')}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer',
                currentTab === 'reports'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              )}
            >
              Reports & Audit
            </button>
            <button
              onClick={() => onSelectTab('approvals')}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer',
                currentTab === 'approvals'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              )}
            >
              Approvals
            </button>
          </div>

          {/* Right Status Indicator & Reset */}
          <div className="flex items-center space-x-3">
            {/* Breaker Badge */}
            <div
              className={cn(
                'flex items-center space-x-2 px-3 py-1.5 rounded-full border text-xs font-bold transition-all',
                badge.bg
              )}
            >
              <span className={cn('w-2 h-2 rounded-full', badge.dot)} />
              <span>{badge.label}</span>
            </div>

            <button
              onClick={onReset}
              disabled={isResetting}
              title="Reset Breaker & Policy History"
              className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw className={cn('w-4 h-4', isResetting && 'animate-spin')} />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
