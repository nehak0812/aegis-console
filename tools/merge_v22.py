"""Three-way merge helper for AEGIS v2.2 — compare and port, don't rebuild.

    base   = the v2.0 package everyone started from      (merge_package/base_v2.0)
    ours   = the v2.2 reference implementation           (merge_package/v2.2)
    theirs = your deployed code (v2.0 + your own changes, e.g. CRT-/DOM-/BGP-/LOOK- rules, xlsx export, v2.0.1/v2.1 work)

For every file it decides, without guessing:
    identical / only-theirs-changed  → keep yours
    only-ours-changed                → take ours (safe: you never touched it)
    new-in-ours                      → add it
    both-changed                     → 3-way merge with `git merge-file` (keeps both sides' edits; conflicts are marked)

Dry run by default; writes MERGE_REPORT.md into --theirs. Use --apply to write files (on a fresh git branch!).
    python tools/merge_v22.py --base ../merge_package/base_v2.0 --ours ../merge_package/v2.2 --theirs . [--apply]
Requires git on PATH. Never touches data/, .venv/, node_modules/, web/dist/ or .git/.
"""
import argparse
import filecmp
import os
import shutil
import subprocess
import sys

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "data", "__pycache__", ".pytest_cache", "legacy_v1"}
TEXT_EXT = {".py", ".ts", ".tsx", ".js", ".json", ".md", ".txt", ".css", ".html", ".toml", ".yml", ".yaml", ".cfg", ".ini", ""}


def files(root: str) -> set[str]:
    out = set()
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in fs:
            if f.endswith((".zip", ".sqlite", ".sqlite-wal", ".sqlite-shm", ".pyc")):
                continue
            out.add(os.path.relpath(os.path.join(d, f), root).replace("\\", "/"))
    return out


def _norm(path: str) -> bytes:
    """Content with line endings normalised — CRLF vs LF (Windows vs Linux checkouts) must never look like a change."""
    with open(path, "rb") as f:
        data = f.read()
    return data.replace(b"\r\n", b"\n") if os.path.splitext(path)[1] in TEXT_EXT else data


def same(a: str, b: str) -> bool:
    if not (os.path.exists(a) and os.path.exists(b)):
        return False
    return filecmp.cmp(a, b, shallow=False) or _norm(a) == _norm(b)


def _copy_keep_eol(src: str, dst: str) -> None:
    """Write src into dst, keeping dst's existing line-ending style (or src's for new files)."""
    if os.path.exists(dst) and os.path.splitext(dst)[1] in TEXT_EXT:
        crlf = b"\r\n" in open(dst, "rb").read()
        data = _norm(src)
        with open(dst, "wb") as f:
            f.write(data.replace(b"\n", b"\r\n") if crlf else data)
    else:
        shutil.copy2(src, dst)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--ours", required=True)
    ap.add_argument("--theirs", required=True)
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    B, O, T = files(a.base), files(a.ours), files(a.theirs)
    rows = {"take-ours": [], "new-in-ours": [], "keep-theirs": [], "merged-clean": [], "merged-CONFLICT": [], "theirs-only": [], "deleted-in-ours": []}
    for rel in sorted(B | O | T):
        b, o, t = (os.path.join(x, rel) for x in (a.base, a.ours, a.theirs))
        in_b, in_o, in_t = rel in B, rel in O, rel in T
        if in_o and not in_b:
            if not in_t:
                rows["new-in-ours"].append(rel)
                if a.apply:
                    os.makedirs(os.path.dirname(t) or ".", exist_ok=True)
                    shutil.copy2(o, t)
            elif same(o, t):
                rows["keep-theirs"].append(rel)
            else:  # both sides added the same path independently — merge against an empty base
                rows["merged-CONFLICT" if _merge(t, None, o, a.apply) else "merged-clean"].append(rel)
            continue
        if in_b and not in_o:
            rows["deleted-in-ours"].append(rel)  # reported only; never deleted automatically
            continue
        if not in_b and not in_o:
            rows["theirs-only"].append(rel)
            continue
        if not in_t:
            rows["new-in-ours"].append(rel)
            if a.apply:
                os.makedirs(os.path.dirname(t) or ".", exist_ok=True)
                shutil.copy2(o, t)
            continue
        ours_changed, theirs_changed = not same(b, o), not same(b, t)
        if not ours_changed:
            rows["keep-theirs"].append(rel)
        elif not theirs_changed:
            rows["take-ours"].append(rel)
            if a.apply:
                _copy_keep_eol(o, t)
        elif same(o, t):
            rows["keep-theirs"].append(rel)
        else:
            rows["merged-CONFLICT" if _merge(t, b, o, a.apply) else "merged-clean"].append(rel)
    rep = ["# AEGIS v2.2 merge report", "", f"mode: {'APPLIED' if a.apply else 'dry run (nothing written)'}", ""]
    for k, v in rows.items():
        rep.append(f"## {k} ({len(v)})")
        rep += [f"- `{x}`" for x in v] or ["- (none)"]
        rep.append("")
    rep.append("Next: resolve every `<<<<<<< yours / >>>>>>> v2.2` block in merged-CONFLICT files (keep both sides' intent), "
               "then run `pytest -q` and `cd web && npm ci && npm run build`.")
    with open(os.path.join(a.theirs, "MERGE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(rep))
    print("\n".join(f"{k}: {len(v)}" for k, v in rows.items()))
    print("report: MERGE_REPORT.md")
    return 0


def _merge(theirs: str, base: str | None, ours: str, apply: bool) -> bool:
    """git merge-file: 3-way merge into a temp copy of theirs; returns True when conflicts remain."""
    ext = os.path.splitext(theirs)[1]
    if ext not in TEXT_EXT:
        return True
    import tempfile
    crlf = b"\r\n" in open(theirs, "rb").read()
    with tempfile.TemporaryDirectory() as td:
        def norm_copy(src, name):  # all three sides merged as LF text so line endings never cause conflicts
            p = os.path.join(td, name)
            with open(p, "wb") as f:
                f.write(_norm(src) if src else b"")
            return p
        cur, bse, ors = norm_copy(theirs, "cur"), norm_copy(base, "base"), norm_copy(ours, "ours")
        r = subprocess.run(["git", "merge-file", "-L", "yours", "-L", "base v2.0", "-L", "v2.2", cur, bse, ors], capture_output=True)
        if r.returncode < 0 or r.returncode > 127:
            print("git merge-file failed:", theirs, r.stderr.decode(errors="replace"), file=sys.stderr)
            return True
        if apply:
            data = open(cur, "rb").read()
            with open(theirs, "wb") as f:
                f.write(data.replace(b"\n", b"\r\n") if crlf else data)
        return r.returncode > 0


if __name__ == "__main__":
    raise SystemExit(main())
