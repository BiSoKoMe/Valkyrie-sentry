import { useEffect, useState } from 'react';
import { getApplications } from '../lib/api';
import { AppWindow, AlertTriangle, RefreshCw } from 'lucide-react';

interface App {
  process_name: string;
  pid: number;
  connections: number;
  flagged: number;
  tracker_alerts: number;
  risk_score: number;
}

function RiskBar({ score }: { score: number }) {
  const barColor =
    score >= 80 ? 'bg-valk-green' :
    score >= 50 ? 'bg-valk-yellow' :
    'bg-valk-red';
  const textColor =
    score >= 80 ? 'text-valk-green' :
    score >= 50 ? 'text-valk-yellow' :
    'text-valk-red';
  return (
    <div className="flex items-center gap-2 min-w-[110px]">
      <div className="flex-1 h-1.5 bg-valk-panel rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: `${Math.max(2, score)}%` }}
        />
      </div>
      <span className={`text-xs font-bold tabular-nums w-7 text-right ${textColor}`}>{score}</span>
    </div>
  );
}

export default function Applications() {
  const [apps, setApps] = useState<App[]>([]);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const d = await getApplications();
      setApps(d.applications || []);
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Applications</h2>
          <p className="text-valk-muted text-sm mt-1">Process privacy auditing and connection analysis</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-3 py-2 bg-valk-card border border-valk-border rounded-lg text-sm hover:border-valk-cyan transition-colors"
        >
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      <div className="bg-valk-card border border-valk-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-valk-panel text-valk-muted">
              <tr>
                <th className="px-5 py-3 text-left font-medium">Process</th>
                <th className="px-5 py-3 text-left font-medium">PID</th>
                <th className="px-5 py-3 text-left font-medium">Connections</th>
                <th className="px-5 py-3 text-left font-medium">Flagged</th>
                <th className="px-5 py-3 text-left font-medium">Tracker Alerts</th>
                <th className="px-5 py-3 text-left font-medium">Risk Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-valk-border">
              {apps.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-valk-muted">
                    No application data yet. Run scan or watch mode.
                  </td>
                </tr>
              ) : (
                apps.map((a, i) => (
                  <tr
                    key={i}
                    className={`hover:bg-valk-panel/50 transition-colors ${
                      a.risk_score < 40 ? 'bg-valk-red/5' :
                      a.risk_score < 60 ? 'bg-valk-yellow/5' : ''
                    }`}
                  >
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <AppWindow size={15} className="text-valk-blue shrink-0" />
                        <span className="font-mono">{a.process_name}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3 font-mono text-valk-muted text-xs">{a.pid || '—'}</td>
                    <td className="px-5 py-3 tabular-nums">{a.connections}</td>
                    <td className="px-5 py-3">
                      {a.flagged > 0 ? (
                        <span className="flex items-center gap-1 text-valk-red font-medium">
                          <AlertTriangle size={13} />
                          {a.flagged}
                        </span>
                      ) : (
                        <span className="text-valk-muted">—</span>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      {a.tracker_alerts > 0 ? (
                        <span className="text-valk-yellow font-medium tabular-nums">{a.tracker_alerts}</span>
                      ) : (
                        <span className="text-valk-muted">—</span>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      <RiskBar score={a.risk_score} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
