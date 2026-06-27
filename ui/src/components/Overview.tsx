import { useEffect, useState } from 'react';
import { getStats, getStatus, getWifiStatus, startMode, stopMode } from '../lib/api';
import {
  Activity, Shield, Wifi, AlertTriangle, Clock,
  ShieldAlert, Eye, Scan, Radio, Square, ChevronDown, ChevronUp,
  Lock, Globe, WifiOff,
} from 'lucide-react';

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

interface WifiStatus {
  ssid: string;
  security_level: string;
  is_open: boolean;
  dns_hijacked: boolean;
  warnings: string[];
  error?: string;
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

function ShieldIndicator({ label, icon: Icon, ok, detail }: {
  label: string; icon: React.ElementType; ok: boolean | null; detail?: string;
}) {
  const color = ok === null ? 'text-valk-muted' : ok ? 'text-valk-green' : 'text-valk-yellow';
  const bg    = ok === null ? 'bg-valk-panel'  : ok ? 'bg-valk-green/15' : 'bg-valk-yellow/15';
  return (
    <div className={`flex-1 rounded-xl p-4 border ${ok === null ? 'border-valk-border' : ok ? 'border-valk-green/30' : 'border-valk-yellow/30'} ${bg}`}>
      <div className="flex items-center gap-2 mb-1">
        <Icon size={15} className={color} />
        <span className={`text-xs font-semibold uppercase tracking-wide ${color}`}>{label}</span>
      </div>
      <div className={`text-xs ${ok === null ? 'text-valk-muted' : ok ? 'text-valk-green' : 'text-valk-yellow'}`}>
        {ok === null ? 'Inactive' : ok ? (detail || 'Secure') : (detail || 'Warning')}
      </div>
    </div>
  );
}

function formatUptime(s: number) {
  if (s < 60) return `${Math.floor(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

export default function Overview() {
  const [stats, setStats]         = useState<Stats | null>(null);
  const [status, setStatus]       = useState<Status | null>(null);
  const [wifi, setWifi]           = useState<WifiStatus | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

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

  const isRunning  = status?.running ?? false;
  const isShield   = isRunning && status?.mode === 'shield';

  const activateShield = async () => {
    await startMode('shield');
    setTimeout(async () => {
      await fetchData();
      // Load WiFi status once shield is up
      try { setWifi(await getWifiStatus()); } catch (_) {}
    }, 1500);
  };

  const stop = async () => {
    await stopMode();
    setWifi(null);
    setTimeout(fetchData, 1000);
  };

  const start = async (mode: string, opts?: Record<string, unknown>) => {
    await startMode(mode, opts);
    setTimeout(fetchData, 1000);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-valk-muted text-sm mt-1">System status and real-time protection metrics</p>
      </div>

      {/* Hero card */}
      <div className={`rounded-2xl border p-6 transition-all duration-500 ${
        isShield
          ? 'bg-gradient-to-r from-valk-cyan/5 via-valk-purple/5 to-transparent border-valk-cyan/30'
          : isRunning
            ? 'bg-gradient-to-r from-valk-green/5 to-transparent border-valk-green/30'
            : 'bg-valk-card border-valk-border'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center gap-5">
          {/* Animated icon */}
          <div className={`relative w-16 h-16 flex-shrink-0 flex items-center justify-center rounded-2xl ${
            isShield ? 'bg-gradient-to-br from-valk-cyan/20 to-valk-purple/20'
            : isRunning ? 'bg-valk-green/20' : 'bg-valk-panel'
          }`}>
            {isRunning && (
              <span
                className={`absolute inset-0 rounded-2xl animate-ping ${isShield ? 'bg-valk-cyan/20' : 'bg-valk-green/20'}`}
                style={{ animationDuration: '2s' }}
              />
            )}
            <ShieldAlert size={30} className={
              isShield ? 'text-valk-cyan' : isRunning ? 'text-valk-green' : 'text-valk-muted'
            } />
          </div>

          {/* Status text */}
          <div className="flex-1 min-w-0">
            <div className="text-xl font-bold">
              {isShield
                ? 'Maximum Protection Active'
                : isRunning
                  ? `Protected — ${status?.mode ?? ''}`
                  : 'Not Protected'}
            </div>
            <div className="text-sm text-valk-muted mt-1 truncate">
              {isRunning
                ? `Uptime ${formatUptime(status?.uptime ?? 0)} · PID ${status?.pid}`
                : 'Activate Shield for DNS blocking, firewall rules, and WiFi threat detection'}
            </div>
          </div>

          {/* CTA */}
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
              <button
                onClick={activateShield}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-bold text-valk-bg transition-all hover:opacity-90"
                style={{ background: 'linear-gradient(135deg, #00d4ff 0%, #a855f7 100%)' }}
              >
                <ShieldAlert size={15} />
                Activate Shield
              </button>
            )}
          </div>
        </div>

        {/* Shield indicators — shown when shield is active */}
        {isShield && (
          <div className="flex gap-3 mt-5">
            <ShieldIndicator
              label="DNS Protection"
              icon={Globe}
              ok={true}
              detail={`${stats?.dns_blocked ?? 0} blocked`}
            />
            <ShieldIndicator
              label="App Firewall"
              icon={Lock}
              ok={true}
              detail={`${stats?.firewall_blocks ?? 0} rules`}
            />
            <ShieldIndicator
              label="WiFi Guard"
              icon={wifi ? (wifi.is_open || wifi.dns_hijacked ? WifiOff : Wifi) : Wifi}
              ok={wifi ? (!wifi.is_open && !wifi.dns_hijacked) : null}
              detail={wifi ? (wifi.warnings[0] || `${wifi.ssid} — ${wifi.security_level}`) : 'Checking…'}
            />
          </div>
        )}
      </div>

      {/* Advanced modes disclosure (shown when idle) */}
      {!isRunning && (
        <div className="bg-valk-card border border-valk-border rounded-xl overflow-hidden">
          <button
            onClick={() => setShowAdvanced(v => !v)}
            className="w-full flex items-center justify-between px-5 py-4 text-sm text-valk-muted hover:text-valk-text transition-colors"
          >
            <span className="font-medium">Advanced Modes</span>
            {showAdvanced ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
          </button>
          {showAdvanced && (
            <div className="px-4 pb-4 grid grid-cols-1 sm:grid-cols-3 gap-3 border-t border-valk-border pt-4">
              <button
                onClick={() => start('sinkhole')}
                className="flex items-center gap-3 px-4 py-3 bg-valk-panel border border-valk-border rounded-xl text-sm hover:border-valk-cyan transition-all group"
              >
                <Shield size={18} className="text-valk-muted group-hover:text-valk-cyan transition-colors shrink-0" />
                <div className="text-left">
                  <div className="font-medium group-hover:text-valk-cyan transition-colors">DNS Sinkhole</div>
                  <div className="text-xs text-valk-muted mt-0.5">Block trackers via DNS only</div>
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
                onClick={() => start('scan')}
                className="flex items-center gap-3 px-4 py-3 bg-valk-panel border border-valk-border rounded-xl text-sm hover:border-valk-purple transition-all group"
              >
                <Scan size={18} className="text-valk-muted group-hover:text-valk-purple transition-colors shrink-0" />
                <div className="text-left">
                  <div className="font-medium group-hover:text-valk-purple transition-colors">Live Scanner</div>
                  <div className="text-xs text-valk-muted mt-0.5">Audit active connections</div>
                </div>
              </button>
              <button
                onClick={() => start('monitor')}
                className="flex items-center gap-3 px-4 py-3 bg-valk-panel border border-valk-border rounded-xl text-sm hover:border-valk-green transition-all group"
              >
                <Activity size={18} className="text-valk-muted group-hover:text-valk-green transition-colors shrink-0" />
                <div className="text-left">
                  <div className="font-medium group-hover:text-valk-green transition-colors">Monitor</div>
                  <div className="text-xs text-valk-muted mt-0.5">24/7 tracking alerts</div>
                </div>
              </button>
              <button
                onClick={() => start('watch', { with_dns: true })}
                className="flex items-center gap-3 px-4 py-3 bg-valk-panel border border-valk-border rounded-xl text-sm hover:border-valk-blue transition-all group"
              >
                <Radio size={18} className="text-valk-muted group-hover:text-valk-blue transition-colors shrink-0" />
                <div className="text-left">
                  <div className="font-medium group-hover:text-valk-blue transition-colors">Watch + DNS</div>
                  <div className="text-xs text-valk-muted mt-0.5">Traffic + DNS sinkhole</div>
                </div>
              </button>
            </div>
          )}
        </div>
      )}

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard title="DNS Blocked"        value={stats?.dns_blocked ?? 0}       icon={Shield}        color="text-valk-red"    bg="bg-valk-red/10" />
        <StatCard title="DNS Allowed"        value={stats?.dns_allowed ?? 0}        icon={Activity}      color="text-valk-green"  bg="bg-valk-green/10" />
        <StatCard title="Tracker Alerts"     value={stats?.tracking_alerts ?? 0}    icon={AlertTriangle} color="text-valk-yellow" bg="bg-valk-yellow/10" />
        <StatCard title="Active Connections" value={stats?.active_connections ?? 0} icon={Wifi}          color="text-valk-cyan"   bg="bg-valk-cyan/10" />
        <StatCard title="Firewall Blocks"    value={stats?.firewall_blocks ?? 0}    icon={Shield}        color="text-valk-purple" bg="bg-valk-purple/10" />
        <StatCard title="Uptime"             value={status ? formatUptime(status.uptime) : '—'} icon={Clock} color="text-valk-blue" bg="bg-valk-blue/10" />
      </div>
    </div>
  );
}
