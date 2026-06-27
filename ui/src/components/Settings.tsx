import { useEffect, useState } from 'react';
import { getStatus, getSettings, startMode, stopMode } from '../lib/api';
import { Shield, Download, Save, Server } from 'lucide-react';

interface SettingsData {
  dns_upstream: string;
  dns_port: number;
  alert_cooldown: number;
  api_bind: string;
  api_port: number;
  blocklist_dir: string;
  db_path: string;
}

export default function Settings() {
  const [status, setStatus] = useState<any>(null);
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [mode, setMode] = useState('idle');
  const [dnsPort, setDnsPort] = useState(5353);

  useEffect(() => {
    getStatus().then(s => { setStatus(s); setMode(s.mode); });
    getSettings().then(setSettings);
  }, []);

  const handleStart = async (m: string) => {
    await startMode(m, { dns_port: dnsPort, api_bind: '0.0.0.0' });
    setTimeout(() => getStatus().then(s => setStatus(s)), 1500);
  };

  const handleStop = async () => {
    await stopMode();
    setTimeout(() => getStatus().then(s => setStatus(s)), 1500);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Settings</h2>
        <p className="text-valk-muted text-sm mt-1">Control center configuration</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Service Control */}
        <div className="bg-valk-card border border-valk-border rounded-xl p-5 space-y-4">
          <h3 className="font-bold flex items-center gap-2">
            <Server size={18} className="text-valk-cyan" />
            Service Control
          </h3>
          <div className="flex items-center justify-between">
            <span className="text-sm">Current Mode</span>
            <span className={`px-2 py-1 rounded text-xs font-bold ${status?.running ? 'bg-valk-green/20 text-valk-green' : 'bg-valk-red/20 text-valk-red'}`}>
              {mode}
            </span>
          </div>
          <div>
            <label className="text-sm text-valk-muted block mb-1">DNS Port</label>
            <input
              type="number"
              value={dnsPort}
              onChange={e => setDnsPort(Number(e.target.value))}
              className="w-full bg-valk-panel border border-valk-border rounded-lg px-3 py-2 text-sm focus:border-valk-cyan focus:outline-none"
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => handleStart('sinkhole')}
              className="px-3 py-2 bg-valk-blue text-white rounded-lg text-sm hover:bg-valk-blue/80 transition-colors"
            >
              Sinkhole
            </button>
            <button
              onClick={() => handleStart('monitor')}
              className="px-3 py-2 bg-valk-purple text-white rounded-lg text-sm hover:bg-valk-purple/80 transition-colors"
            >
              Monitor
            </button>
            <button
              onClick={() => handleStart('watch')}
              className="px-3 py-2 bg-valk-yellow text-white rounded-lg text-sm hover:bg-valk-yellow/80 transition-colors"
            >
              Watch
            </button>
            <button
              onClick={() => handleStart('scan')}
              className="px-3 py-2 bg-valk-green text-white rounded-lg text-sm hover:bg-valk-green/80 transition-colors"
            >
              Scan
            </button>
          </div>
          <button
            onClick={handleStop}
            className="w-full px-3 py-2 bg-valk-red/20 text-valk-red border border-valk-red/30 rounded-lg text-sm hover:bg-valk-red/30 transition-colors"
          >
            Emergency Stop
          </button>
        </div>

        {/* Configuration */}
        <div className="bg-valk-card border border-valk-border rounded-xl p-5 space-y-4">
          <h3 className="font-bold flex items-center gap-2">
            <Shield size={18} className="text-valk-cyan" />
            Configuration
          </h3>
          {settings && (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm">DNS Upstream</span>
                <span className="font-mono text-valk-cyan">{settings.dns_upstream}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">API Bind</span>
                <span className="font-mono text-valk-cyan">{settings.api_bind}:{settings.api_port}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Alert Cooldown</span>
                <span className="font-mono text-valk-cyan">{settings.alert_cooldown}s</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Blocklist Dir</span>
                <span className="font-mono text-valk-cyan text-xs">{settings.blocklist_dir}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Database</span>
                <span className="font-mono text-valk-cyan text-xs">{settings.db_path}</span>
              </div>
            </>
          )}
          <div className="flex gap-2 pt-2">
            <button className="flex items-center gap-2 px-3 py-2 bg-valk-card border border-valk-border rounded-lg text-sm hover:border-valk-cyan transition-colors">
              <Download size={16} />
              Export Logs
            </button>
            <button className="flex items-center gap-2 px-3 py-2 bg-valk-card border border-valk-border rounded-lg text-sm hover:border-valk-cyan transition-colors">
              <Save size={16} />
              Backup Config
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
