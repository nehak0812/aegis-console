"""Start AEGIS: API + console, with autonomous collection in the background.

Local:   python run.py                      → http://127.0.0.1:8000
Railway: PORT is injected by the platform  → binds 0.0.0.0:$PORT
"""
import os
import sys

import uvicorn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    port = int(os.environ.get("PORT") or os.environ.get("AEGIS_PORT") or "8000")
    host = os.environ.get("HOST") or ("0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
    print("AEGIS — Cyber Risk Operations Center")
    print(f"  console      http://{host}:{port}")
    print(f"  data         {os.environ.get('AEGIS_DATA_DIR', 'data/')}")
    print(f"  access       {'password protected' if os.environ.get('AEGIS_PASSWORD') else 'open (set AEGIS_PASSWORD to protect)'}")
    print("  guardrails   passive only · open sources only · credentials never stored")
    # one worker only: the collector scheduler and SQLite database live in this process
    uvicorn.run("aegis.api:app", host=host, port=port, reload=False, workers=1, log_level="warning",
                proxy_headers=True, forwarded_allow_ips="*")
