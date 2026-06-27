import { NavLink } from 'react-router-dom';
import { useEffect, useState } from 'react';
import {
  LayoutDashboard, Activity, Monitor, AppWindow,
  Shield, Settings, Power, ShieldAlert,
} from 'lucide-react';
import { getStatus, stopMode } from '../lib/api';

const nav = [
  { to: '/',            label: 'Overview',     icon: LayoutDashboard },
  { to: '/activity',    label: 'Live Activity', icon: Activity },
  { to: '/devices',     label: 'Devices',       icon: Monitor },
  { to: '/applications',label: 'Applications',  icon: AppWindow },
  { to: '/blocklist',   label: 'Blocklist',     icon: Shield },
  { to: '/settings',    label: 'Settings',      icon: Settings },
];

export default function Sidebar() {
  const [running, setRunning] = useState(false);
  const [mode, setMode] = useState('idle');

  useEffect(() => {
    const poll = async () => {
      try {
        const s = await getStatus();
        setRunning(s.running);
        setMode(s.mode);
      } catch {}
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => clearInterval(id);
  }, []);

  const handleStop = async () => {
    try { await stopMode(); } catch {}
    setRunning(false);
    setMode('idle');
  };

  return (
    <aside className="w-60 bg-valk-panel border-r border-valk-border flex flex-col shrink-0">
      {/* Branding */}
      <div className="p-4 border-b border-valk-border">
        <div className="flex items-center gap-2.5 mb-3">
          <ShieldAlert size={22} className="text-valk-cyan shrink-0" />
          <div>
            <h1 className="text-sm font-bold text-valk-cyan tracking-[0.2em] leading-none">VALKYRIE</h1>
            <p className="text-[10px] text-valk-muted tracking-widest mt-0.5">PRIVACY ENGINE</p>
          </div>
        </div>
        {/* Live status badge */}
        <div className={`flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium border ${
          running
            ? 'bg-valk-green/10 text-valk-green border-valk-green/20'
            : 'bg-valk-card text-valk-muted border-valk-border'
        }`}>
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${running ? 'bg-valk-green animate-pulse' : 'bg-valk-muted'}`} />
          {running ? mode.toUpperCase() + ' ACTIVE' : 'IDLE — NO PROTECTION'}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
        {nav.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all border-l-2 ${
                isActive
                  ? 'bg-valk-cyan/10 text-valk-cyan border-valk-cyan'
                  : 'text-valk-muted hover:text-valk-text hover:bg-valk-card border-transparent'
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Emergency Stop */}
      <div className="p-3 border-t border-valk-border">
        <button
          onClick={handleStop}
          disabled={!running}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-sm font-medium transition-all
            border border-transparent text-valk-red
            hover:bg-valk-red/10 hover:border-valk-red/30
            disabled:opacity-25 disabled:cursor-not-allowed"
        >
          <Power size={15} />
          Emergency Stop
        </button>
      </div>
    </aside>
  );
}
