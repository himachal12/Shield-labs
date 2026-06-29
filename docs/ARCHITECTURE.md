# ShieldLabs Architecture

ShieldLabs is organized as one FastAPI backend and one Vite React frontend.

- Backend application code lives under `backend/app`.
- Scanner implementations live under `backend/app/scanners`.
- Database entities, schemas, and repository functions live under `backend/app/models`.
- API route handlers live under `backend/app/api`.
- Frontend source lives under `frontend/src`.

The reconciliation preserved the complete pattern scanner, semantic analyzer, fix generator, repository handler, LLM utility, queue-style scan API, and legacy scan CRUD API.
