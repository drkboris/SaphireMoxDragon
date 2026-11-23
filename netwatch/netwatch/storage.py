"""Save each sweep to disk so later runs (and a future `diff`) can compare.

Layout inside the data directory:
    run-YYYYMMDD-HHMMSS.json   one file per sweep (history)
    latest.json                copy of the newest run
"""

import json
from datetime import datetime
from pathlib import Path

from .models import HostResult

DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "netwatch"


def build_run_record(
    targets: dict[str, str], all_results: dict[str, list[HostResult]]
) -> dict:
    """Shape sweep results into the JSON structure we store."""
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "networks": {
            label: {
                "cidr": targets[label],
                "scanned": len(results),
                "hosts": [r.to_dict() for r in results if r.alive],
            }
            for label, results in all_results.items()
        },
    }


def save_run(record: dict, data_dir: Path = DEFAULT_DATA_DIR) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_path = data_dir / f"run-{stamp}.json"
    record["run_file"] = run_path.name  # lets later steps update this exact run
    text = json.dumps(record, indent=2)
    run_path.write_text(text)
    (data_dir / "latest.json").write_text(text)
    return run_path


def update_latest(record: dict, data_dir: Path = DEFAULT_DATA_DIR) -> None:
    """Write an enriched record back to latest.json and to the run file it came from."""
    text = json.dumps(record, indent=2)
    (data_dir / "latest.json").write_text(text)
    run_file = record.get("run_file")
    if run_file:
        run_path = data_dir / Path(run_file).name  # .name guards against odd paths
        if run_path.exists():
            run_path.write_text(text)


def load_latest(data_dir: Path = DEFAULT_DATA_DIR) -> dict | None:
    path = data_dir / "latest.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())
