import { useEffect, useState, FormEvent } from 'react';
import { getBlockedDomains, addDomain, removeDomain, reloadBlocklists, exportLogs, updateBlocklists, getBlocklistCount } from '../lib/api';
import { Shield, Plus, Trash2, RefreshCw, Download, CloudDownload } from 'lucide-react';

interface Domain {
  domain: string;
  action: string;
  category: string;
  count: number;
  last_seen: string;
}

export default function Blocklist() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [newDomain, setNewDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState('');
  const [totalDomains, setTotalDomains] = useState<number | null>(null);

  const load = async () => {
    setLoading(true);
    const [d, cnt] = await Promise.all([getBlockedDomains(200), getBlocklistCount().catch(() => null)]);
    setDomains(d.domains || []);
    if (cnt?.total_domains != null) setTotalDomains(cnt.total_domains);
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;
    await addDomain(newDomain.trim());
    setNewDomain('');
    load();
  };

  const handleRemove = async (domain: string) => {
    await removeDomain(domain);
    load();
  };

  const handleUpdate = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const res = await updateBlocklists();
      setUpdateMsg(res.message || 'Download started. Restart Valkyrie when complete.');
    } catch {
      setUpdateMsg('Failed to start update. Is valkyrie_api running?');
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Blocklist Management</h2>
          <p className="text-valk-muted text-sm mt-1">
            Manage tracker and surveillance domains
            {totalDomains != null && (
              <span className="ml-2 text-valk-cyan font-semibold">
                — {totalDomains.toLocaleString()} domains protected
              </span>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={load}
            className="flex items-center gap-2 px-3 py-2 bg-valk-card border border-valk-border rounded-lg text-sm hover:border-valk-cyan transition-colors"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button
            onClick={() => reloadBlocklists()}
            className="flex items-center gap-2 px-3 py-2 bg-valk-blue text-white rounded-lg text-sm hover:bg-valk-blue/80 transition-colors"
          >
            <Shield size={16} />
            Reload All
          </button>
          <button
            onClick={exportLogs}
            className="flex items-center gap-2 px-3 py-2 bg-valk-green text-white rounded-lg text-sm hover:bg-valk-green/80 transition-colors"
          >
            <Download size={16} />
            Export Logs
          </button>
        </div>
      </div>

      {/* Community blocklist updater */}
      <div className="bg-valk-card border border-valk-border rounded-xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="font-bold flex items-center gap-2">
              <CloudDownload size={18} className="text-valk-cyan" />
              Community Blocklists
            </h3>
            <p className="text-valk-muted text-sm mt-1">
              Download 6 community lists (~1M+ domains): Steven Black, OISD, AdGuard DNS, HaGeZi Pro++, URLhaus malware, EasyPrivacy. Covers every major ad network, data broker, malware host, and telemetry endpoint.
            </p>
            {updateMsg && (
              <p className={`text-sm mt-2 ${updateMsg.startsWith('Failed') ? 'text-valk-red' : 'text-valk-green'}`}>
                {updateMsg}
              </p>
            )}
          </div>
          <button
            onClick={handleUpdate}
            disabled={updating}
            className="shrink-0 flex items-center gap-2 px-4 py-2 bg-valk-cyan text-valk-bg rounded-lg text-sm font-bold hover:bg-valk-cyan/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <CloudDownload size={16} className={updating ? 'animate-pulse' : ''} />
            {updating ? 'Updating…' : 'Update Now'}
          </button>
        </div>
      </div>

      <form onSubmit={handleAdd} className="flex gap-2">
        <input
          type="text"
          value={newDomain}
          onChange={e => setNewDomain(e.target.value)}
          placeholder="Add tracker domain (e.g., tracker.example.com)"
          className="flex-1 bg-valk-card border border-valk-border rounded-lg px-3 py-2 text-sm focus:border-valk-cyan focus:outline-none"
        />
        <button type="submit" className="flex items-center gap-2 px-4 py-2 bg-valk-red text-white rounded-lg text-sm hover:bg-valk-red/80 transition-colors">
          <Plus size={16} />
          Block Domain
        </button>
      </form>

      <div className="bg-valk-card border border-valk-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-valk-panel text-valk-muted">
              <tr>
                <th className="px-5 py-3 text-left font-medium">Domain</th>
                <th className="px-5 py-3 text-left font-medium">Category</th>
                <th className="px-5 py-3 text-left font-medium">Action</th>
                <th className="px-5 py-3 text-left font-medium">Hits</th>
                <th className="px-5 py-3 text-left font-medium">Last Seen</th>
                <th className="px-5 py-3 text-left font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-valk-border">
              {domains.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-valk-muted">
                    No blocked domains recorded yet.
                  </td>
                </tr>
              ) : (
                domains.map((d, i) => (
                  <tr key={i} className="hover:bg-valk-panel/50">
                    <td className="px-5 py-3 font-mono text-valk-cyan">{d.domain}</td>
                    <td className="px-5 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        d.category === 'TELEMETRY' ? 'bg-valk-red/20 text-valk-red' :
                        d.category === 'AD-TRACKER' ? 'bg-valk-yellow/20 text-valk-yellow' :
                        d.category === 'DATA-BROKER' ? 'bg-valk-purple/20 text-valk-purple' :
                        'bg-valk-blue/20 text-valk-blue'
                      }`}>
                        {d.category}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-valk-muted">{d.action}</td>
                    <td className="px-5 py-3 font-bold text-valk-red">{d.count}</td>
                    <td className="px-5 py-3 text-xs text-valk-muted">{d.last_seen?.slice(0, 19).replace('T', ' ')}</td>
                    <td className="px-5 py-3">
                      <button
                        onClick={() => handleRemove(d.domain)}
                        className="text-valk-red hover:text-valk-red/80 transition-colors"
                      >
                        <Trash2 size={16} />
                      </button>
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
