import { Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Overview from './components/Overview';
import LiveActivity from './components/LiveActivity';
import Devices from './components/Devices';
import Applications from './components/Applications';
import Blocklist from './components/Blocklist';
import Settings from './components/Settings';
import Terminal from './components/Terminal';

export default function App() {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-valk-bg text-valk-text">
      <Sidebar />
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <div className="flex-1 overflow-y-auto p-4 md:p-6">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/activity" element={<LiveActivity />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/applications" element={<Applications />} />
            <Route path="/blocklist" element={<Blocklist />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </div>
        <Terminal />
      </main>
    </div>
  );
}
