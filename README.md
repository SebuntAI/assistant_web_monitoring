# Assistant web monitoring

This agent receives web activity events from the Assistant and the local proxy. It stores short-term events as JSONL and structured history in its PostgreSQL database, and uses Ollama for event analysis and embeddings.

- Python package: `src/assistant_web_monitoring/`
- Database schema: `db/schema.sql`
- Runtime service: `assistant-web-monitoring.service`
- Installed launcher: `/opt-ai/assistant_web_monitoring/bin/assistant-web-monitoring`
- Source entry point: `src/assistant_web_monitoring/monitor.py`

The Python package uses only the standard library. It expects its service account, runtime paths, local PostgreSQL socket, and Ollama endpoint to be configured by the host deployment.
