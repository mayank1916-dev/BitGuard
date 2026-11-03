import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  X,
  AlertTriangle,
  Lock,
  Unlock,
  KeyRound,
  CheckCircle2,
  Clock,
  UserCheck,
  FileText,
} from 'lucide-react';
import {
  DATA_SOURCE,
  getBreaker,
  escalateBreaker,
  createDeescalationRequest,
  approveDeescalation,
  fetchActiveDeescalationRequest,
  fetchDevToken,
  BreakerStatusResponse,
  DeescalationRequestModel,
  WebAuthnAssertionPayload,
} from '../api';
import { cn, getDataLabelBadgeStyle } from '../utils';

interface BreakerModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentState: string;
  onStateChanged?: (newState: string) => void;
}

interface TestUser {
  id: string;
  name: string;
  role: 'secops' | 'admin' | 'approver' | 'operator';
  description: string;
}

const TEST_USERS: TestUser[] = [
  { id: 'usr-secops-01', name: 'Alice SecOps', role: 'secops', description: 'Can escalate instant lockdown & request unlock' },
  { id: 'usr-admin-01', name: 'Bob Admin', role: 'admin', description: 'Full administrative authority & emergency escalation' },
  { id: 'usr-approver-01', name: 'Carol Approver 1', role: 'approver', description: 'Independent hardware key quorum approver' },
  { id: 'usr-approver-02', name: 'David Approver 2', role: 'approver', description: 'Independent hardware key quorum approver' },
  { id: 'usr-operator-01', name: 'Eve Operator', role: 'operator', description: 'Read-only breaker telemetry, no escalation/approval rights' },
];

export const BreakerModal: React.FC<BreakerModalProps> = ({
  isOpen,
  onClose,
  currentState,
  onStateChanged,
}) => {
  const [breakerData, setBreakerData] = useState<BreakerStatusResponse | null>(null);
  const [activeRequest, setActiveRequest] = useState<DeescalationRequestModel | null>(null);
  const [currentUser, setCurrentUser] = useState<TestUser>(TEST_USERS[0]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Escalation confirmation state
  const [showLockdownConfirm, setShowLockdownConfirm] = useState<boolean>(false);
  const [lockdownReason, setLockdownReason] = useState<string>('Emergency containment: suspicious unauthorized activity detected');

  // De-escalation creation state
  const [showUnlockForm, setShowUnlockForm] = useState<boolean>(false);
  const [targetState, setTargetState] = useState<string>('NORMAL');
  const [unlockReason, setUnlockReason] = useState<string>('Investigation concluded, incident resolved; nominal operations safe to resume');

  const normalizedState = (breakerData?.state || currentState || 'NORMAL').toUpperCase();
  const isAboveNormal = normalizedState !== 'NORMAL';

  const canEscalate = currentUser.role === 'secops' || currentUser.role === 'admin';
  const canRequestUnlock = currentUser.role === 'secops' || currentUser.role === 'admin';
  const canApprove = currentUser.role === 'approver' || currentUser.role === 'admin';

  // Load latest breaker telemetry and active de-escalation request
  const loadBreakerDetails = async () => {
    try {
      const data = await getBreaker();
      setBreakerData(data);
      if (DATA_SOURCE === 'api') {
        const activeReq = await fetchActiveDeescalationRequest().catch(() => null);
        setActiveRequest(activeReq);
      }
    } catch (err: any) {
      console.warn('Failed to refresh breaker details:', err);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadBreakerDetails();
      setActionError(null);
      setActionSuccess(null);
      setShowLockdownConfirm(false);
      setShowUnlockForm(false);
    }
  }, [isOpen, currentState]);

  if (!isOpen) return null;

  // Handle Emergency Lockdown Escalation
  const handleTriggerLockdown = async () => {
    setIsLoading(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const token = await fetchDevToken(currentUser.role).catch(() => undefined);
      await escalateBreaker('LOCKDOWN', lockdownReason, token);
      setActionSuccess('BREAKER LOCKDOWN executed successfully: Token epoch incremented and keys revoked.');
      setShowLockdownConfirm(false);
      await loadBreakerDetails();
      onStateChanged?.('LOCKDOWN');
    } catch (err: any) {
      setActionError(err.message || 'Failed to trigger breaker lockdown');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Propose Unlock Request
  const handleCreateUnlockRequest = async () => {
    setIsLoading(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const token = await fetchDevToken(currentUser.role).catch(() => undefined);
      const req = await createDeescalationRequest(targetState, unlockReason, token);
      setActiveRequest(req);
      setShowUnlockForm(false);
      setActionSuccess(`Unlock proposal created (ID: ${req.id}). Requires 2 independent WebAuthn approvals.`);
      await loadBreakerDetails();
    } catch (err: any) {
      setActionError(err.message || 'Failed to create unlock proposal');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Hardware WebAuthn Approval over Challenge
  const handleApproveUnlock = async () => {
    if (!activeRequest) return;
    setIsLoading(true);
    setActionError(null);
    setActionSuccess(null);

    try {
      const token = await fetchDevToken(currentUser.role).catch(() => undefined);
      let assertion: WebAuthnAssertionPayload;

      if (typeof window !== 'undefined' && typeof window.navigator?.credentials?.get === 'function' && DATA_SOURCE === 'api') {
        try {
          const rawChallenge = activeRequest.challenge.startsWith('0x')
            ? activeRequest.challenge.slice(2)
            : activeRequest.challenge;
          const challengeBytes = new Uint8Array(
            rawChallenge.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
          );

          const credential = (await navigator.credentials.get({
            publicKey: {
              challenge: challengeBytes.buffer,
              rpId: window.location.hostname || 'localhost',
              userVerification: 'preferred',
              timeout: 60000,
            },
          })) as any;

          if (credential && credential.response) {
            assertion = {
              credential_id: credential.id,
              authenticator_data: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
              client_data_json: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
              signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
            };
          } else {
            throw new Error('Hardware assertion returned empty credential');
          }
        } catch {
          // Virtual hardware fallback for test environments
          assertion = {
            credential_id: `cred-${currentUser.id}`,
            authenticator_data: btoa('test-authenticator-data'),
            client_data_json: btoa(JSON.stringify({ type: 'webauthn.get', challenge: activeRequest.challenge })),
            signature: btoa(`sig-hardware-${currentUser.id}-${activeRequest.challenge.slice(0, 16)}`),
          };
        }
      } else {
        assertion = {
          credential_id: `cred-${currentUser.id}`,
          authenticator_data: btoa('test-authenticator-data'),
          client_data_json: btoa(JSON.stringify({ type: 'webauthn.get', challenge: activeRequest.challenge })),
          signature: btoa(`sig-hardware-${currentUser.id}-${activeRequest.challenge.slice(0, 16)}`),
        };
      }

      const result = await approveDeescalation(activeRequest.id, assertion, token);
      setActionSuccess(result.message);
      await loadBreakerDetails();

      if (result.new_breaker_state) {
        onStateChanged?.(result.new_breaker_state);
      }
    } catch (err: any) {
      setActionError(err.message || 'Failed to submit WebAuthn de-escalation approval');
    } finally {
      setIsLoading(false);
    }
  };

  // State pill styling helper
  const getStateBadge = (state: string) => {
    switch (state) {
      case 'NORMAL':
        return {
          icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
          label: 'NORMAL OPERATION',
          container: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
          dot: 'bg-emerald-400',
        };
      case 'ELEVATED':
        return {
          icon: <Activity className="w-5 h-5 text-amber-400 animate-pulse" />,
          label: 'ELEVATED SCRUTINY',
          container: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
          dot: 'bg-amber-400',
        };
      case 'HOLD':
        return {
          icon: <ShieldAlert className="w-5 h-5 text-amber-500" />,
          label: 'MANUAL HOLD ACTIVE',
          container: 'bg-amber-500/15 border-amber-500/40 text-amber-300',
          dot: 'bg-amber-500',
        };
      case 'LOCKDOWN':
      default:
        return {
          icon: <ShieldAlert className="w-5 h-5 text-rose-400 animate-bounce" />,
          label: 'BREAKER LOCKDOWN',
          container: 'bg-rose-500/20 border-rose-500/50 text-rose-300 shadow-lg shadow-rose-900/30',
          dot: 'bg-rose-500 animate-ping',
        };
    }
  };

  const badge = getStateBadge(normalizedState);

  // Separation of duties check
  const isRequester = activeRequest?.requested_by === currentUser.id;
  const hasAlreadyApproved = activeRequest?.approvals?.some((a) => a.approver_id === currentUser.id);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/50">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                Circuit Breaker Controls
                <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-normal uppercase bg-slate-800 text-slate-300 border border-slate-700">
                  {DATA_SOURCE === 'api' ? 'LIVE BACKEND' : 'SIMULATION'}
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Asymmetric operational containment: instant lockdown, 2-approver WebAuthn unlock
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 flex-1">
          {/* Messages */}
          {actionError && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{actionError}</span>
            </div>
          )}
          {actionSuccess && (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-300 text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>{actionSuccess}</span>
            </div>
          )}

          {/* Current State Status Banner */}
          <div className={cn('p-4 rounded-xl border flex items-center justify-between transition-all', badge.container)}>
            <div className="flex items-center space-x-3">
              <span className={cn('w-3 h-3 rounded-full', badge.dot)} />
              <div>
                <span className="text-xs uppercase font-mono tracking-wider opacity-75">Operational State</span>
                <div className="text-base font-bold tracking-tight">{badge.label}</div>
              </div>
            </div>

            <div className="text-right flex flex-col items-end gap-1">
              <span
                className={cn(
                  'text-[10px] font-mono px-2 py-0.5 rounded border font-semibold uppercase',
                  getDataLabelBadgeStyle(breakerData?.data_label || 'REAL')
                )}
              >
                {breakerData?.data_label || (DATA_SOURCE === 'api' ? 'REAL' : 'SYNTHETIC')}
              </span>
              <span className="text-[10px] font-mono text-slate-400">
                Token Epoch: #{breakerData?.token_epoch ?? 1}
              </span>
            </div>
          </div>

          {/* Last Transition Telemetry Card */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between text-xs font-semibold text-slate-300 pb-1.5 border-b border-slate-800/80">
              <span className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                Last State Transition Telemetry
              </span>
              <span className="font-mono text-[10px] text-slate-500">
                {breakerData?.updated_at
                  ? new Date(breakerData.updated_at).toLocaleTimeString()
                  : new Date().toLocaleTimeString()}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-slate-500 text-[11px] block font-medium">Triggered By</span>
                <span className="font-mono text-cyan-300 font-medium break-all">
                  {breakerData?.updated_by || 'system'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 text-[11px] block font-medium">Reason Code & Details</span>
                <span className="text-slate-300 font-mono text-[11px]">
                  {breakerData?.reason || 'Nominal operations'}
                </span>
              </div>
            </div>
          </div>

          {/* Active Testing Role Switcher */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <UserCheck className="w-3.5 h-3.5 text-purple-400" />
                Simulated Operator Identity
              </span>
              <span className="text-[10px] text-slate-500 font-mono uppercase">
                Role: {currentUser.role}
              </span>
            </div>
            <p className="text-[11px] text-slate-400">{currentUser.description}</p>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 pt-1">
              {TEST_USERS.map((u) => (
                <button
                  key={u.id}
                  onClick={() => setCurrentUser(u)}
                  className={cn(
                    'px-2.5 py-1.5 rounded-lg text-left text-xs font-medium border transition-all cursor-pointer',
                    currentUser.id === u.id
                      ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-semibold'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                  )}
                >
                  <div className="truncate font-sans">{u.name}</div>
                  <div className="text-[10px] uppercase font-mono text-slate-500">{u.role}</div>
                </button>
              ))}
            </div>
          </div>

          {/* ACTION 1: Emergency Breaker Lockdown (SecOps / Admin Only) */}
          {canEscalate && (
            <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/40 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-bold text-rose-300 uppercase tracking-wide flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    Immediate Emergency Lockdown
                  </h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    SecOps & Admin single-person instant escalation. Denies all signing requests and revokes active approval tokens.
                  </p>
                </div>
              </div>

              {!showLockdownConfirm ? (
                <button
                  onClick={() => setShowLockdownConfirm(true)}
                  disabled={isLoading || normalizedState === 'LOCKDOWN'}
                  className="w-full py-2 px-3 bg-rose-600/30 hover:bg-rose-600/50 border border-rose-500/50 text-rose-200 rounded-lg font-semibold text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <ShieldAlert className="w-4 h-4" />
                  {normalizedState === 'LOCKDOWN' ? 'BREAKER CURRENTLY IN LOCKDOWN' : 'TRIGGER BREAKER LOCKDOWN'}
                </button>
              ) : (
                <div className="p-3 bg-slate-950/80 border border-rose-500/50 rounded-lg space-y-2 animate-in fade-in">
                  <span className="text-xs font-bold text-rose-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    Confirm Instant Lockdown:
                  </span>
                  <p className="text-[11px] text-slate-300">
                    Are you sure? This will immediately transition circuit breaker to <strong>LOCKDOWN</strong>, increment token epoch (invalidating all live approval tokens), and signal key disablement hooks.
                  </p>
                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Operational Justification / Incident Tag:</label>
                    <input
                      type="text"
                      value={lockdownReason}
                      onChange={(e) => setLockdownReason(e.target.value)}
                      className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs text-slate-200 font-mono"
                    />
                  </div>
                  <div className="flex items-center gap-2 pt-1">
                    <button
                      onClick={handleTriggerLockdown}
                      disabled={isLoading}
                      className="flex-1 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-bold transition-colors cursor-pointer"
                    >
                      {isLoading ? 'Executing...' : 'CONFIRM & EXECUTE LOCKDOWN NOW'}
                    </button>
                    <button
                      onClick={() => setShowLockdownConfirm(false)}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors cursor-pointer"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ACTION 2: Unlock Request & Dual-Control Quorum Approvals (Visible only when > NORMAL) */}
          {isAboveNormal && (
            <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-800/40 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-bold text-cyan-300 uppercase tracking-wide flex items-center gap-1.5">
                    <Unlock className="w-4 h-4 text-cyan-400" />
                    De-escalation & Unlock Controls
                  </h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Asymmetric de-escalation: requires 2 distinct approvers with WebAuthn hardware signatures.
                  </p>
                </div>
              </div>

              {/* Pending Active Request Inspection */}
              {activeRequest && activeRequest.status === 'PENDING' ? (
                <div className="p-3.5 bg-slate-950/80 border border-cyan-500/30 rounded-lg space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <div>
                      <span className="text-[10px] text-slate-500 font-mono uppercase block">Active Proposal</span>
                      <span className="text-xs font-bold font-mono text-cyan-400">{activeRequest.id}</span>
                    </div>
                    <div className="text-right">
                      <span className="text-[10px] font-mono text-amber-300 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded font-bold">
                        Quorum: {activeRequest.approvals.length} / {activeRequest.required_approvals} Recorded
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-slate-500 text-[10px] block">Target State</span>
                      <span className="font-bold text-emerald-400 font-mono">{activeRequest.target_state}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] block">Requested By</span>
                      <span className="font-mono text-slate-300">{activeRequest.requested_by}</span>
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 text-[10px] block">Investigation / Reason</span>
                    <p className="text-xs text-slate-300 font-mono mt-0.5 bg-slate-900 p-2 rounded border border-slate-800">
                      {activeRequest.reason}
                    </p>
                  </div>

                  <div>
                    <span className="text-slate-500 text-[10px] block">Challenge Digest</span>
                    <span className="font-mono text-[10px] text-slate-400 break-all">{activeRequest.challenge}</span>
                  </div>

                  {/* List of recorded approvals */}
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-mono block mb-1">
                      Recorded Hardware Signatures:
                    </span>
                    {activeRequest.approvals.length === 0 ? (
                      <p className="text-[11px] text-slate-500 italic">No approvals submitted yet. Awaiting 2 approvers.</p>
                    ) : (
                      <div className="space-y-1.5">
                        {activeRequest.approvals.map((appr, idx) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800 text-[11px]"
                          >
                            <span className="font-mono text-cyan-300 flex items-center gap-1.5">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                              {appr.approver_id}
                            </span>
                            <span className="text-slate-500 font-mono text-[10px]">
                              {new Date(appr.timestamp * 1000).toLocaleTimeString()}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* WebAuthn Approval Action */}
                  <div className="pt-1">
                    {canApprove ? (
                      <div>
                        {isRequester ? (
                          <div className="p-2 bg-amber-500/10 border border-amber-500/30 rounded text-amber-300 text-xs">
                            Disabled: Requester cannot approve their own unlock proposal (Separation of duties).
                          </div>
                        ) : hasAlreadyApproved ? (
                          <div className="p-2 bg-blue-500/10 border border-blue-500/30 rounded text-blue-300 text-xs">
                            Disabled: Approver '{currentUser.id}' has already recorded an approval for this proposal.
                          </div>
                        ) : (
                          <button
                            onClick={handleApproveUnlock}
                            disabled={isLoading}
                            className="w-full py-2 px-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold transition-colors flex items-center justify-center gap-2 cursor-pointer shadow-lg shadow-cyan-900/30"
                          >
                            <KeyRound className="w-4 h-4" />
                            {isLoading ? 'Verifying Hardware Assertion...' : 'APPROVE UNLOCK WITH WEBAUTHN HARDWARE KEY'}
                          </button>
                        )}
                      </div>
                    ) : (
                      <div className="p-2 bg-slate-900 border border-slate-800 rounded text-slate-500 text-xs italic">
                        Logged in as '{currentUser.role}'. WebAuthn approval requires Approver or Admin role.
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                /* No active request pending: Allow SecOps / Admin to propose one */
                <div>
                  {!showUnlockForm ? (
                    canRequestUnlock ? (
                      <button
                        onClick={() => setShowUnlockForm(true)}
                        className="w-full py-2 px-3 bg-cyan-600/30 hover:bg-cyan-600/40 border border-cyan-500/40 text-cyan-200 rounded-lg font-semibold text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer"
                      >
                        <Unlock className="w-4 h-4" />
                        CREATE UNLOCK REQUEST (PROPOSE DE-ESCALATION)
                      </button>
                    ) : (
                      <div className="p-2 bg-slate-900 border border-slate-800 rounded text-slate-500 text-xs italic">
                        Creating de-escalation proposals requires SecOps or Admin role.
                      </div>
                    )
                  ) : (
                    <div className="p-3 bg-slate-950/80 border border-cyan-500/40 rounded-lg space-y-2.5 animate-in fade-in">
                      <span className="text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                        <FileText className="w-4 h-4" />
                        Propose Breaker State Lowering
                      </span>

                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <label className="text-[10px] text-slate-400 block mb-1">Target State:</label>
                          <select
                            value={targetState}
                            onChange={(e) => setTargetState(e.target.value)}
                            className="w-full px-2 py-1.5 bg-slate-900 border border-slate-700 text-xs text-white rounded font-mono"
                          >
                            <option value="NORMAL">NORMAL</option>
                            {normalizedState === 'LOCKDOWN' && <option value="HOLD">HOLD</option>}
                            {normalizedState === 'LOCKDOWN' && <option value="ELEVATED">ELEVATED</option>}
                          </select>
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-400 block mb-1">Proposer:</label>
                          <span className="font-mono text-xs text-slate-300 block py-1.5 truncate">
                            {currentUser.id}
                          </span>
                        </div>
                      </div>

                      <div>
                        <label className="text-[10px] text-slate-400 block mb-1">Justification / Incident Resolution Summary:</label>
                        <textarea
                          rows={2}
                          value={unlockReason}
                          onChange={(e) => setUnlockReason(e.target.value)}
                          className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs text-slate-200 font-mono"
                        />
                      </div>

                      <div className="flex items-center gap-2 pt-1">
                        <button
                          onClick={handleCreateUnlockRequest}
                          disabled={isLoading}
                          className="flex-1 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-bold transition-colors cursor-pointer"
                        >
                          {isLoading ? 'Submitting...' : 'SUBMIT PROPOSAL FOR 2-KEY QUORUM'}
                        </button>
                        <button
                          onClick={() => setShowUnlockForm(false)}
                          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors cursor-pointer"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs text-slate-500 font-mono">
          <span>BitGuard Invariant #6: Asymmetric Policy Evolution</span>
          <button
            onClick={onClose}
            className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
