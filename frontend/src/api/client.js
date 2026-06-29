const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export async function getHealth() {
  const response = await fetch(API_BASE_URL + '/api/health');
  if (!response.ok) throw new Error('Health check failed');
  return response.json();
}

export async function queueCodeScan(repoUrl) {
  const response = await fetch(API_BASE_URL + '/api/scan/code', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo_url: repoUrl }),
  });
  if (!response.ok) throw new Error('Scan request failed');
  return response.json();
}
