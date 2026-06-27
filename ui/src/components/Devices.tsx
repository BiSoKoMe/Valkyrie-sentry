import { useEffect, useState } from 'react';
import { getDevices } from '../lib/api';
import { Monitor, Globe, Clock, Shield } from 'lucide-react';

interface Device {
  ip: string;
  mac: string;
  hostname: string;
  vendor: string;
  privacy_score: number;
  event_count: number;
  last_seen: string;
}

function ScoreBadge({ score }: { score: number }) {
  const cls = score >= 80 ? 'text-valk-green' : score >= 50 ? 'text-valk-yellow' : 'text-valk-red';
  return <span className={`font-bold ${cls}`}>{score}/100</span>;
}

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);

  const load = async () => {
    const d = await getDevices();
    setDevices(d.devices || []);
  };

  useEffect(() => { load(); const id = setInterval(load, 8000); return () => clearInterval(id); }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Devices</h2>
        <p className="text-valk-muted text-sm mt-1">LAN devices observed by Valkyrie</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {devices.length === 0 && (
          <div className="col-span-full bg-valk-card border border-valk-border rounded-xl p-8 text-center text-valk-muted">
            No devices found yet. Start sinkhole or monitor mode.
          </div>
        )}
        {devices.map((d, i) => (
          <div key={i} className="bg-valk-card border border-valk-border rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Monitor size={18} className="text-valk-cyan" />
                <span className="font-bold">{d.hostname}</span>
              </div>
              <ScoreBadge score={d.privacy_score} />
            </div>
            <div className="space-y-1 text-sm">
              <div className="flex items-center gap-2 text-valk-muted">
                <Globe size={14} />
                <span className="font-mono">{d.ip}</span>
              </div>
              <div className="flex items-center gap-2 text-valk-muted">
                <Shield size={14} />
                <span className="font-mono">{d.mac}</span>
              </div>
              <div className="flex items-center gap-2 text-valk-muted">
                <Monitor size={14} />
                <span>{d.vendor}</span>
              </div>
              <div className="flex items-center gap-2 text-valk-muted">
                <Clock size={14} />
                <span className="text-xs">{d.last_seen?.slice(0, 19).replace('T', ' ')}</span>
              </div>
            </div>
            <div className="pt-2 border-t border-valk-border text-xs text-valk-muted">
              {d.event_count} events detected
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
