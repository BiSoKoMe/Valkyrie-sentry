import { useEffect, useState } from 'react';
import { getDnsLog, getStats } from '../lib/api';
import { RefreshCw, Shield, AlertTriangle, CheckCircle, Globe, Search } from 'lucide-react';

interface DnsEvent {
  ts: string;
  action: string;
  domain: string;
  category: string;
  severity: number;
  details: string;
}

type Filter = 'all' | 'blocked' | 'tracker' | 'clean';

const ACTION_META: Record<string, { label: string; color: string; bg: string; dot: string }> = {
  blocked_dns:    { label: 'BLOCKED', color: 'text-valk-red',    bg: 'bg-valk-red/20',    dot: 'bg-valk-red' },
  tracking_alert: { label: 'TRACKER', color: 'text-valk-yellow', bg: 'bg-valk-yellow/20', dot: 'bg-valk-yellow' },
  dns_query:      { label: 'CLEAN',   color: 'text-valk-green',  bg: 'bg-valk-green/20',  dot: 'bg-valk-green' },
};

function ActionBadge({ action }: { action: string }) {
  const meta = ACTION_META[action] ?? { label: action.toUpperCase(), color: 'text-valk-muted', bg: 'bg-valk-card', dot: 'bg-valk-muted' };
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-bold ${meta.bg} ${meta.color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
      {meta.label}
    </span>
  );
}

export default function LiveActivity() {
  const [events, setEvents] = useState<DnsEvent[]>([]);
  const [filter, setFilter] = useState<Filter>('all');
  const [hours, setHours] = useState(1);
  const [search, setSearch] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = async () => {
    setRefreshing(true);
    try {
      const log = await getDnsLog(hours, 500);
      setEvents(log.events || []);
    } catch {}
    setRefreshing(false);
  };

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 3000);
    return () => clearInterval(id);
  }, [hours]);

  const counts = {
    all:     events.length,
    blocked: events.filter(e => e.action === 'blocked_dns').length,
    tracker: events.filter(e => e.action === 'tracking_alert').length,
    clean:   events.filter(e => e.action === 'dns_query').length,
  };

  const filtered = events.filter(e => {
    const matchFilter =
      filter === 'all' ||
      (filter === 'blocked' && e.action === 'blocked_dns') ||
      (filter === 'tracker' && e.action === 'tracking_alert') ||
      (filter === 'clean'   && e.action === 'dns_query');
    const matchSearch = !search || e.domain?.toLowerCase().includes(search.toLowerCase());
    return matchFilter && matchSearch;
  });

  const tabs: { key: Filter; label: string; icon: React.ElementType; color: string; count: number }[] = [
    { key: 'all',     label: 'All',      icon: Globe,          color: 'text-valk-cyan',   count: counts.all },
    { key: 'blocked', label: 'Blocked',  icon: Shield,         color: 'text-valk-red',    count: counts.blocked },
    { key: 'tracker', label: 'Trackers', icon: AlertTriangle,  color: 'text-valk-yellow', count: counts.tracker },
    { key: 'clean',   label: 'Clean',    icon: CheckCircle,    color: 'text-valk-green',  count: counts.clean },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold">Live Activity</h2>
          <p className="text-valk-muted text-sm mt-1">All DNS queries — every site you visit, in real time</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Search */}
          <div className="relative">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-valk-muted pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter domain…"
              className="pl-8 pr-3 py-2 bg-valk-card border border-valk-border rounded-lg text-sm w-44 focus:border-valk-cyan focus:outline-none placeholder:text-valk-muted"
            />
          </div>
          {/* Time window */}
          <select
            value={hours}
            onChange={e => setHours(Number(e.target.value))}
            className="bg-valk-card border border-valk-border rounded-lg px-3 py-2 text-sm focus:border-valk-cyan focus:outline-none"
          >
            <option value={1}>Last 1h</option>
            <option value={6}>Last 6h</option>
            <option value={24}>Last 24h</option>
          </select>
          <button
            onClick={fetchData}
            className="flex items-center gap-2 px-3 py-2 bg-valk-card border border-valk-border rounded-lg text-sm hover:border-valk-cyan transition-colors"
          >
            <RefreshCw size={15} className={refreshing ? 'animate-spin text-valk-cyan' : ''} />
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setFilter(t.key)}
            className={`bg-valk-card border rounded-xl p-4 text-left transition-all hover:scale-[1.01] ${
              filter === t.key ? 'border-valk-cyan shadow-sm shadow-valk-cyan/10' : 'border-valk-border'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-valk-muted text-xs font-medium uppercase tracking-wide">{t.label}</span>
              <t.icon size={15} className={t.color} />
            </div>
            <div className={`text-2xl font-bold tabular-nums ${t.color}`}>{t.count}</div>
          </button>
        ))}
      </div>

      {/* Filter tabs */}
      <div className="flex gap-1 border-b border-valk-border">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setFilter(t.key)}
            className={`flex items-center gap-1.5 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              filter === t.key
                ? `border-valk-cyan ${t.color}`
                : 'border-transparent text-valk-muted hover:text-valk-text'
            }`}
          >
            <t.icon size={13} />
            {t.label}
            <span className={`text-xs px-1.5 py-0.5 rounded tabular-nums ${
              filter === t.key ? 'bg-valk-cyan/20' : 'bg-valk-card'
            }`}>{t.count}</span>
          </button>
        ))}
      </div>

      {/* Event table */}
      <div className="bg-valk-card border border-valk-border rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-valk-border flex items-center justify-between">
          <h3 className="font-bold text-sm">
            {filtered.length} {filter === 'all' ? 'total' : filter} {filtered.length === 1 ? 'event' : 'events'}
            {search && <span className="text-valk-muted font-normal"> matching <span className="text-valk-cyan">"{search}"</span></span>}
          </h3>
          {events.length === 0 && (
            <span className="text-xs text-valk-muted">Start DNS sinkhole or monitor mode</span>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-valk-panel text-valk-muted">
              <tr>
                <th className="px-5 py-2 text-left font-medium w-24">Time</th>
                <th className="px-5 py-2 text-left font-medium w-28">Status</th>
                <th className="px-5 py-2 text-left font-medium">Domain</th>
                <th className="px-5 py-2 text-left font-medium w-32">Category</th>
                <th className="px-5 py-2 text-left font-medium w-12">Sev</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-valk-border">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-12 text-center text-valk-muted">
                    {events.length === 0
                      ? 'No DNS events yet — start sinkhole or monitor mode, then browse the web.'
                      : search
                        ? `No results for "${search}"`
                        : `No ${filter} events in this time window.`}
                  </td>
                </tr>
              ) : (
                filtered.slice(0, 200).map((e, i) => {
                  const meta = ACTION_META[e.action];
                  return (
                    <tr
                      key={i}
                      className={`hover:bg-valk-panel/50 transition-colors ${
                        e.action === 'blocked_dns'    ? 'bg-valk-red/5' :
                        e.action === 'tracking_alert' ? 'bg-valk-yellow/5' : ''
                      }`}
                    >
                      <td className="px-5 py-2 text-valk-muted font-mono text-xs whitespace-nowrap">
                        {e.ts?.slice(11, 19)}
                      </td>
                      <td className="px-5 py-2">
                        <ActionBadge action={e.action} />
                      </td>
                      <td className={`px-5 py-2 font-mono text-sm ${meta?.color ?? 'text-valk-cyan'}`}>
                        {e.domain}
                      </td>
                      <td className="px-5 py-2 text-valk-muted text-xs">{e.category || '—'}</td>
                      <td className="px-5 py-2 text-xs">
                        {e.severity > 0 && (
                          <span className={`font-bold tabular-nums ${
                            e.severity >= 4 ? 'text-valk-red' :
                            e.severity >= 3 ? 'text-valk-yellow' : 'text-valk-muted'
                          }`}>
                            {e.severity}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {filtered.length > 200 && (
          <div className="px-5 py-3 border-t border-valk-border text-xs text-valk-muted text-center">
            Showing 200 of {filtered.length} events — narrow the time window or filter to see more
          </div>
        )}
      </div>
    </div>
  );
}
