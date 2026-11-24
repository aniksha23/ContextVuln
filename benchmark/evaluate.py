import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.agents.ast_agent import check_reachability


def evaluate():
    root = Path(__file__).resolve().parent
    data = json.loads((root / "ground_truth.json").read_text(encoding="utf-8"))
    rows = []
    tp = fp = tn = fn = unknown = 0

    for case in data["cases"]:
        result = check_reachability(str(root / case["path"]), case["symbols"])
        if result.is_reachable:
            status = "reachable"
        elif result.confidence == 0.0:
            status = "not_observed"
        else:
            status = "unknown"

        retained = status != "not_observed"
        truth = case["reachable"]
        tp += bool(retained and truth)
        fp += bool(retained and not truth)
        tn += bool(not retained and not truth)
        fn += bool(not retained and truth)
        unknown += status == "unknown"

        rows.append(
            {
                "id": case["id"],
                "expected_reachable": truth,
                "status": status,
                "confidence": result.confidence,
                "call_path": result.call_path,
                "retained_alert": retained,
            }
        )

    n = len(rows)
    metrics = {
        "cases": n,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "alert_reduction_rate": (tn + fn) / n if n else 0,
        "precision": tp / (tp + fp) if tp + fp else None,
        "false_negative_rate": fn / (tp + fn) if tp + fn else None,
        "unknown": unknown,
        "decision_coverage": (n - unknown) / n if n else 0,
    }
    output = {"scope": data["description"], "metrics": metrics, "results": rows}
    (root / "results.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    return output


if __name__ == "__main__":
    evaluate()
