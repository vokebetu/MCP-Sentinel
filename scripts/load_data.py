import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLES = {"seed": ROOT / "data" / "seed", "full": ROOT / "data" / "bundle"}


def run(*args):
    print("+", " ".join(args), flush=True)
    subprocess.run([sys.executable, "-I", *args], check=True, cwd=ROOT)


def main():
    parser = argparse.ArgumentParser(description="Load an evidence bundle into PostgreSQL and validate it, or add new tables.")
    parser.add_argument("dataset", choices=["seed", "full", "validate", "migrate"])
    parser.add_argument("--bundle", help="bundle directory; defaults to data/seed or data/bundle")
    args = parser.parse_args()
    if args.dataset == "migrate":
        sys.path.insert(0, str(ROOT / "scripts"))
        from sentinel_common import apply_migrations, connect
        with connect() as conn:
            applied = apply_migrations(conn)
        print("applied: " + ", ".join(applied) if applied else "database is up to date")
        return
    bundle = Path(args.bundle) if args.bundle else BUNDLES["full" if args.dataset == "validate" else args.dataset]
    for name in ("registry_snapshot.jsonl.gz", "registry_snapshot_meta.json", "evidence.jsonl.gz"):
        if not (bundle / name).exists():
            raise SystemExit(f"{bundle / name} is missing. See README: Rebuild the full database.")
    if args.dataset != "validate":
        run("scripts/import_registry.py", "--bundle", str(bundle))
        run("scripts/import_enrichment.py", "--bundle", str(bundle))
    run("scripts/validate_database.py", "--bundle", str(bundle))


if __name__ == "__main__":
    main()
