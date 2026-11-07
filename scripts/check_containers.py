"""Build first; then run four isolated bank-node containers and four PostgreSQL instances."""

import json
from datetime import datetime, timezone
from pathlib import Path

from certify.containers import run

if __name__ == "__main__":
    output = Path(".local") / (
        "container-acceptance-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    )
    report = run(output)
    print(
        json.dumps(
            {k: v for k, v in report.items() if k not in ["privacy", "isolation"]},
            indent=2,
        )
    )
    print("Full report:", output / "report.json")
