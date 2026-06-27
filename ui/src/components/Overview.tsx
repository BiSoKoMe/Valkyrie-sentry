import { useEffect, useState } from 'react';
import { getStats, getStatus, startMode, stopMode } from '../lib/api';
import { Activity, Shield, Wifi, AlertTriangle, Clock, ShieldAlert, Eye, Scan, Radio, Square } from 'lucide-react';

interface Stats {
  total_events: number;
  active_connections: number;
  tracking_alerts: number;
  dns_blocked: number;
  dns_allowed: number;
  connections_flagged: number;
  firewall_blocks: number;
}

interface Status {
  running: boolean;
  mode: string;
  pid: number | null;
  uptime: number;
}

function StatCard({
  title, value, icon: Icon, color, bg,
}: {
  title: string;
  value: string | number;
  icon: React.ElementType;
  color: string;
  bg: string;
}) {
  return (
    <div className="bg-valk-card border border-valk-border rounded-xl p-5 hover:border-valk-border/60 transition-colors">
      <div className="flex items-center justify-between mb-3">
        <span className="text-valk-muted text-xs font-medium uppercase tracking-wide">{title}</span>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${bg} ${color}`}>
          <Icon size={15} />
        </div>
      </div>
      <div className={`text-3xl font-bold tabular-nums ${color}`}>{value}</div>
    </div>
  );
}

function formatUptime(s: number) {
  if (s < 60) return `${Math.floor(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

export default function Overview() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [status, setStatus] = useState<Status | null>(null);

  const fetchData = async () => {
    const [s, st] = await Promise.all([getStats(), getStatus()]);
    setStats(s);
    setStatus(st);
  };

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 3000);
    return () => clearInterval(id);
  }, []);

  const start = async (mode: string, opts?: Record<string, unknown>) => {
    await startMode(mode, opts);
    setTimeout(fetchData, 1000);
  };

  const stop = async () => {
    await stopMode();
    setTimeout(fetchData, 1000);
  };

  const isRunning = status?.running ?? false;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-valk-muted text-sm mt-1">System status and real-time protection metrics</p>
      </div>

      {/* Hero status card */}
      <div className={`rounded-2xl border p-6 transition-all duration-500 ${
        isRunning
          ? 'bg-gradient-to-r from-valk-green/5 to-transparent border-valk-green/30'
          : 'bg-valk-card border-valk-border'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center gap-5">
          {/* Animated shield */}
          <div className={`relative w-16 h-16 flex-shrink-0 flex items-center justify-center rounded-2xl ${
            isRunning ? 'bg-valk-green/20' : 'bg-valk-panel'
          }`}>
            {isRunning && (
              <span
                className="absolute inset-0 rounded-2xl bg-valk-green/20 animate-ping"
                style={{ animationDuration: '2s' }}
              />
            )}
            <ShieldAlert size={30} className={isRunning ? 'text-valk-green' : 'text-valk-muted'} />
          </div>

          {/* Status text */}
          <div className="flex-1 min-w-0">
            <div className="text-xl font-bold">
              {isRunning ? `Protected — ${status?.mode ?? ''}` : 'Not Protected'}
            </div>
            <div className="text-sm text-valk-muted mt-1 truncate">
              {isRunning
                ? `Uptime ${formatUptime(status?.uptime ?? 0)} · PID ${status?.pid}`
                : 'Choose a protection mode to begin monitoring your network'}
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex gap-2 flex-wrap shrink-0">
            {isRunning ? (
              <button
                onClick={stop}
                className="flex items-center gap-2 px-4 py-2 bg-valk-red/20 text-valk-red border border-valk-red/30 rounded-lg text-sm font-medium hover:bg-valk-red/30 transition-colors"
              >
                <Square size={13} fill="currentColor" />
                Stop
              </button>
            ) : (
              <>
                <button
                  onClick={() => start('sinkhole')}
                  className="flex items-center gap-2 px-4 py-2 bg-valk-cyan text-valk-bg rounded-lg text-sm font-bold hover:bg-valk-cyan/80 transition-colors"
                >
                  <Shield size={14} />
                  Sinkhole
                </button>
                <button
                  onClick={() => start('monitor')}
                  className="flex items-center gap-2 px-4 py-2 bg-valk-card border border-valk-border rounded-lg text-sm hover:border-valk-purple hover:text-valk-purple transition-colors"
                >
                  <Eye size={14} />
                  Monitor
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard title="DNS Blocked"        value={stats?.dns_blocked ?? 0}       icon={Shield}        color="text-valk-red"    bg="bg-valk-red/10" />
        <StatCard title="DNS Allowed"        value={stats?.dns_allowed ?? 0}        icon={Activity}      color="text-valk-green"  bg="bg-valk-green/10" />
        <StatCard title="Tracker Alerts"     value={stats?.tracking_alerts ?? 0}    icon={AlertTriangle} color="text-valk-yellow" bg="bg-valk-yellow/10" />
        <StatCard title="Active Connections" value={stats?.active_connections ?? 0} icon={Wifi}          color="text-valk-cyan"   bg="bg-valk-cyan/10" />
        <StatCard title="Firewall Blocks"    value={stats?.firewall_blocks ?? 0}    icon={Shield}        color="text-valk-purple" bg="bg-valk-purple/10" />
        <StatCard title="Uptime"             value={status ? formatUptime(status.uptime) : '—'} icon={Clock} color="text-valk-blue" bg="bg-valk-blue/10" />
      </div>

      {/* Quick actions */}
      <div className="bg-valk-card border border-valk-border rounded-xl p-5">
        <h3 className="text-xs font-bold uppercase tracking-widest text-valk-muted mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <button
            onClick={() => start('scan')}
            className="flex items-center gap-3 px-4 py-3 bg-valk-panel border border-valk-border rounded-xl text-sm hover:border-valk-cyan transition-all group"
          >
            <Scan size={18} className="text-valk-muted group-hover:text-valk-cyan transition-colors shrink-0" />
            <div className="text-left">
              <div className="font-medium group-hover:text-valk-cyan transition-colors">Live Scanner</div>
              <div className="text-xs text-valk-muted mt-0.5">Audit active connections</div>
            </div>
          </button>
          <button
            onClick={() => start('watch')}
            className="flex items-center gap-3 px-4 py-3 bg-valk-panel border border-valk-border rounded-xl text-sm hover:border-valk-yellow transition-all group"
          >
            <Eye size={18} className="text-valk-muted group-hover:text-valk-yellow transition-colors shrink-0" />
            <div className="text-left">
              <div className="font-medium group-hover:text-valk-yellow transition-colors">Watch Mode</div>
              <div className="text-xs text-valk-muted mt-0.5">Monitor traffic silently</div>
            </div>
          </button>
          <button
            onClick={() => start('watch', { with_dns: true })}
            className="flex items-center gap-3 px-4 py-3 bg-valk-panel border border-valk-border rounded-xl text-sm hover:border-valk-purple transition-all group"
          >
            <Radio size={18} className="text-valk-muted group-hover:text-valk-purple transition-colors shrink-0" />
            <div className="text-left">
              <div className="font-medium group-hover:text-valk-purple transition-colors">Watch + DNS</div>
              <div className="text-xs text-valk-muted mt-0.5">Traffic + DNS sinkhole</div>
            </div>
          </button>
        </div>
      </div>
    </div>
  );
}
