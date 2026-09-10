"""AEGIS 2 — autonomous cyber-risk operations console built only on free, open, passive sources."""
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# AEGIS_DATA_DIR lets a host (e.g. a Railway volume mounted at /data) keep the database across deploys
DATA_DIR = os.environ.get("AEGIS_DATA_DIR") or os.path.join(ROOT, "data")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
os.makedirs(CACHE_DIR, exist_ok=True)
