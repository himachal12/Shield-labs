import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.main import app  # noqa: E402


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get('/api/health')
    assert response.status_code == 200
    assert response.json()['status'] == 'ok'


def test_create_scan_endpoint():
    with TestClient(app) as client:
        response = client.post('/api/v1/scans/', json={'target': 'tests/samples/vulnerable_app.py', 'scan_type': 'code'})
    assert response.status_code == 201
    body = response.json()
    assert body['target'] == 'tests/samples/vulnerable_app.py'
    assert body['scan_type'] == 'code'
    assert body['status'] == 'pending'
