import axios from 'axios';

export const API_BASE = '/api';

export const api = axios.create({ baseURL: API_BASE });

export const startMode = async (mode: string, opts?: Record<string, unknown>) => {
  const res = await api.post('/start', { mode, ...opts });
  return res.data;
};

export const stopMode = async () => {
  const res = await api.post('/stop');
  return res.data;
};

export const getStatus = () => api.get('/status').then(r => r.data);
export const getStats = (hours = 24) => api.get(`/stats?hours=${hours}`).then(r => r.data);
export const getAlerts = (hours = 24, limit = 100) => api.get(`/alerts?hours=${hours}&limit=${limit}`).then(r => r.data);
export const getMitigations = (hours = 24, limit = 100) => api.get(`/mitigations?hours=${hours}&limit=${limit}`).then(r => r.data);
export const getDevices = () => api.get('/devices').then(r => r.data);
export const getApplications = () => api.get('/applications').then(r => r.data);
export const getBlockedDomains = (limit = 100) => api.get(`/blocklist/domains?limit=${limit}`).then(r => r.data);
export const getSettings = () => api.get('/settings').then(r => r.data);

export const addDomain = (domain: string, category = 'AD-TRACKER') =>
  api.post('/blocklist/add', null, { params: { domain, category } }).then(r => r.data);

export const removeDomain = (domain: string) =>
  api.post('/blocklist/remove', null, { params: { domain } }).then(r => r.data);

export const reloadBlocklists = () => api.post('/blocklist/reload').then(r => r.data);

export const getDnsLog = (hours = 1, limit = 500) =>
  api.get(`/dns-log?hours=${hours}&limit=${limit}`).then(r => r.data);

export const updateBlocklists = () =>
  api.post('/blocklist/update').then(r => r.data);

export const startShield = (opts?: Record<string, unknown>) =>
  api.post('/start', { mode: 'shield', ...opts }).then(r => r.data);

export const getWifiStatus = () =>
  api.get('/wifi-status').then(r => r.data);

export const getBlocklistCount = () =>
  api.get('/blocklist/count').then(r => r.data);

export const exportLogs = async () => {
  const res = await api.get('/alerts', { params: { hours: 168, limit: 5000 }, responseType: 'json' });
  const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `valkyrie-logs-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
};
