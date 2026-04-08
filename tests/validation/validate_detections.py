from pathlib import Path
import sys
import yaml

DETECTIONS_ROOT = Path("detections/sentinel")

REQUIRED_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "platform",
    "query_language",
    "logsource",
    "query",
    "severity",
    "risk_score",
    "tactics",
    "techniques",
    "falsepositives",
    "triage",
    "validation",
    "lifecycle",
    "owner",
    "tags",
]

ALLOWED_STATUS = {"experimental", "testing", "stable", "production", "deprecated"}
ALLOWED_LIFECYCLE = {"experimental", "testing", "production", "deprecated"}
ALLOWED_SEVERITY = {"low", "medium", "high", "critical"}


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate_file(path: Path):
    errors = []

    try:
        data = load_yaml(path)
    except Exception as exc:
        return [f"{path}: YAML parse error: {exc}"]

    if not isinstance(data, dict):
        return [f"{path}: root YAML object must be a dictionary"]

    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"{path}: missing required field '{field}'")

    if errors:
        return errors

    if not isinstance(data.get("logsource"), dict):
        errors.append(f"{path}: 'logsource' must be a dictionary")

    if not isinstance(data.get("tags"), list):
        errors.append(f"{path}: 'tags' must be a list")

    if not isinstance(data.get("tactics"), list):
        errors.append(f"{path}: 'tactics' must be a list")

    if not isinstance(data.get("techniques"), list):
        errors.append(f"{path}: 'techniques' must be a list")

    if not isinstance(data.get("falsepositives"), list):
        errors.append(f"{path}: 'falsepositives' must be a list")

    if not isinstance(data.get("triage"), list):
        errors.append(f"{path}: 'triage' must be a list")

    if not isinstance(data.get("validation"), list):
        errors.append(f"{path}: 'validation' must be a list")

    status = str(data.get("status", "")).strip().lower()
    lifecycle = str(data.get("lifecycle", "")).strip().lower()
    severity = str(data.get("severity", "")).strip().lower()

    if status not in ALLOWED_STATUS:
        errors.append(
            f"{path}: invalid status '{data.get('status')}'. Allowed: {sorted(ALLOWED_STATUS)}"
        )

    if lifecycle not in ALLOWED_LIFECYCLE:
        errors.append(
            f"{path}: invalid lifecycle '{data.get('lifecycle')}'. Allowed: {sorted(ALLOWED_LIFECYCLE)}"
        )

    if severity not in ALLOWED_SEVERITY:
        errors.append(
            f"{path}: invalid severity '{data.get('severity')}'. Allowed: {sorted(ALLOWED_SEVERITY)}"
        )

    risk_score = data.get("risk_score")
    if not isinstance(risk_score, int):
        errors.append(f"{path}: 'risk_score' must be an integer")
    elif not 0 <= risk_score <= 100:
        errors.append(f"{path}: 'risk_score' must be between 0 and 100")

    title = str(data.get("title", "")).strip()
    rule_id = str(data.get("id", "")).strip()
    query = str(data.get("query", "")).strip()

    if not title:
        errors.append(f"{path}: 'title' must not be empty")

    if not rule_id.startswith("SENT-"):
        errors.append(f"{path}: 'id' should start with 'SENT-'")

    if not query:
        errors.append(f"{path}: 'query' must not be empty")

    relative_parts = path.relative_to(DETECTIONS_ROOT).parts
    if len(relative_parts) >= 2:
        tactic_folder = relative_parts[0]
        tags = [str(t).strip().lower() for t in data.get("tags", [])]
        if tactic_folder not in tags:
            errors.append(
                f"{path}: expected tactic folder '{tactic_folder}' to appear in tags"
            )

    return errors


def main():
    if not DETECTIONS_ROOT.exists():
        print(f"Detection root not found: {DETECTIONS_ROOT}")
        sys.exit(1)

    detection_files = sorted(DETECTIONS_ROOT.rglob("*.yml")) + sorted(DETECTIONS_ROOT.rglob("*.yaml"))

    if not detection_files:
        print("No detection YAML files found.")
        sys.exit(1)

    all_errors = []
    seen_ids = {}
    seen_titles = {}

    for path in detection_files:
        errors = validate_file(path)
        all_errors.extend(errors)

        try:
            data = load_yaml(path)
            if isinstance(data, dict):
                rule_id = str(data.get("id", "")).strip()
                title = str(data.get("title", "")).strip().lower()

                if rule_id:
                    seen_ids.setdefault(rule_id, []).append(str(path))
                if title:
                    seen_titles.setdefault(title, []).append(str(path))
        except Exception:
            pass

    for rule_id, paths in seen_ids.items():
        if len(paths) > 1:
            all_errors.append(f"Duplicate rule id '{rule_id}' found in: {paths}")

    for title, paths in seen_titles.items():
        if len(paths) > 1:
            all_errors.append(f"Duplicate title '{title}' found in: {paths}")

    if all_errors:
        print("Validation failed:\n")
        for err in all_errors:
            print(f"- {err}")
        sys.exit(1)

    print(f"Validation successful. Checked {len(detection_files)} detection files.")


if __name__ == "__main__":
    main()