import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, ShieldCheck } from 'lucide-react';
import { getHealth, queueCodeScan } from './api/client';
import './styles.css';

function App() {
  const [health, setHealth] = useState(null);
  const [repoUrl, setRepoUrl] = useState('https://github.com/example/vulnerable-app');
  const [result, setResult] = useState(null);

  useEffect(() => {
    getHealth().then(setHealth).catch(() => setHealth({ status: 'offline' }));
  }, []);

  async function submitScan(event) {
    event.preventDefault();
    setResult(await queueCodeScan(repoUrl));
  }

  return (
    <main className="shell">
      <section className="panel">
        <div className="brand"><ShieldCheck size={28} /><h1>ShieldLabs</h1></div>
        <div className="status"><Activity size={18} /> API {health?.status || 'checking'}</div>
        <form onSubmit={submitScan} className="scan-form">
          <label htmlFor="repoUrl">Repository URL</label>
          <input id="repoUrl" value={repoUrl} onChange={(event) => setRepoUrl(event.target.value)} />
          <button type="submit">Queue Scan</button>
        </form>
        {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
