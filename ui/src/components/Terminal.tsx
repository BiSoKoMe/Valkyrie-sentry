import { useEffect, useRef, useState, useCallback } from 'react';
import { ChevronDown, ChevronUp, X } from 'lucide-react';

interface LogMessage {
  type: string;
  data: string;
}

export default function Terminal() {
  const [logs, setLogs] = useState<LogMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const connect = useCallback(() => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/logs`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => { setConnected(false); setTimeout(connect, 2000); };
    ws.onerror = () => setConnected(false);
    ws.onmessage = (event) => {
      try {
        const msg: LogMessage = JSON.parse(event.data);
        if (msg.type === 'log' || msg.type === 'heartbeat') {
          setLogs(prev => [...prev.slice(-500), msg]);
        }
      } catch {
        setLogs(prev => [...prev.slice(-500), { type: 'log', data: event.data }]);
      }
    };
  }, []);

  useEffect(() => {
    connect();
    return () => { wsRef.current?.close(); };
  }, [connect]);

  useEffect(() => {
    if (!collapsed) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, collapsed]);

  const getLogStyle = (data: string): string => {
    if (/TRACKING ALERT/.test(data)) return 'text-valk-yellow';
    if (/BLOCKED/.test(data)) return 'text-valk-red';
    if (/FIREWALL/.test(data)) return 'text-valk-purple';
    if (/error|ERROR|Access is denied|Failed|✗/.test(data)) return 'text-valk-red';
    if (/DNS-SWITCH/.test(data)) return 'text-valk-cyan';
    if (/API/.test(data)) return 'text-valk-green';
    if (/\[ALARM/.test(data)) return 'text-valk-red font-bold';
    if (/\d{2}:\d{2}:\d{2}/.test(data)) return 'text-valk-muted';
    return 'text-valk-text';
  };

  return (
    <div
      className={`bg-valk-panel border-t border-valk-border flex flex-col shrink-0 transition-all duration-200 ${
        collapsed ? 'h-10' : 'h-56'
      }`}
    >
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 h-10 border-b border-valk-border bg-valk-bg shrink-0">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-valk-green animate-pulse' : 'bg-valk-red'}`} />
          <span className="text-xs font-mono font-medium text-valk-muted tracking-wide">
            {connected ? 'TERMINAL' : 'TERMINAL — RECONNECTING'}
          </span>
          {logs.length > 0 && (
            <span className="text-xs text-valk-muted/60 font-mono">{logs.length} lines</span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setLogs([])}
            className="p-1 text-valk-muted hover:text-valk-text transition-colors rounded"
            title="Clear"
          >
            <X size={13} />
          </button>
          <button
            onClick={() => setCollapsed(c => !c)}
            className="p-1 text-valk-muted hover:text-valk-text transition-colors rounded"
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            {collapsed ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {/* Log output */}
      {!collapsed && (
        <div className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed">
          {logs.length === 0 && (
            <span className="text-valk-muted">Waiting for Valkyrie output…</span>
          )}
          {logs.map((l, i) => (
            <div key={i} className={getLogStyle(l.data)}>
              {l.data}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      )}
    </div>
  );
}
