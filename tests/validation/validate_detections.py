from pathlib import Path
import sys
import yaml

DETECTIONS_ROOT = Path("detections/sentinel")

# Full schema for active detections
REQUIRED_ACTIVE_FIELDS = [
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

# Lighter schema for deprecated detections
REQUIRED_DEPRECATED_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "lifecycle",
]

ALLOWED_STATUS = {"experimental", "testing", "stable", "production", "deprecated"}
ALLOWED_LIFECYCLE = {"experimental", "testing", "production", "deprecated"}
ALLOWED_SEVERITY = {"low", "medium", "high", "critical"}


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def is_deprecated_rule(path: Path, data: dict) -> bool:
    if "deprecated" in path.parts:
        return True
    lifecycle = str(data.get("lifecycle", "")).strip().lower()
    status = str(data.get("status", "")).strip().lower()
    return lifecycle == "deprecated" or status == "deprecated"


def validate_common_fields(path: Path, data: dict):
    errors = []

    status = str(data.get("status", "")).strip().lower()
    lifecycle = str(data.get("lifecycle", "")).strip().lower()
    title = str(data.get("title", "")).strip()
    rule_id = str(data.get("id", "")).strip()

    if title == "":
        errors.append(f"{path}: 'title' must not be empty")

    deprecated = is_deprecated_rule(path, data)

    if not deprecated and not rule_id.startswith("SENT-"):
        errors.append(f"{path}: 'id' should start with 'SENT-'")

    if status and status not in ALLOWED_STATUS:
        errors.append(
            f"{path}: invalid status '{data.get('status')}'. Allowed: {sorted(ALLOWED_STATUS)}"
        )

    if lifecycle and lifecycle not in ALLOWED_LIFECYCLE:
        errors.append(
            f"{path}: invalid lifecycle '{data.get('lifecycle')}'. Allowed: {sorted(ALLOWED_LIFECYCLE)}"
        )

    if "logsource" in data and not isinstance(data.get("logsource"), dict):
        errors.append(f"{path}: 'logsource' must be a dictionary")

    return errors


def validate_active_rule(path: Path, data: dict):
    errors = []

    for field in REQUIRED_ACTIVE_FIELDS:
        if field not in data:
            errors.append(f"{path}: missing required field '{field}'")

    if errors:
        return errors

    errors.extend(validate_common_fields(path, data))

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

    severity = str(data.get("severity", "")).strip().lower()
    if severity not in ALLOWED_SEVERITY:
        errors.append(
            f"{path}: invalid severity '{data.get('severity')}'. Allowed: {sorted(ALLOWED_SEVERITY)}"
        )

    risk_score = data.get("risk_score")
    if not isinstance(risk_score, int):
        errors.append(f"{path}: 'risk_score' must be an integer")
    elif not 0 <= risk_score <= 100:
        errors.append(f"{path}: 'risk_score' must be between 0 and 100")

    query = str(data.get("query", "")).strip()
    if not query:
        errors.append(f"{path}: 'query' must not be empty")

    return errors


def validate_deprecated_rule(path: Path, data: dict):
    errors = []

    for field in REQUIRED_DEPRECATED_FIELDS:
        if field not in data:
            errors.append(f"{path}: missing required field '{field}'")

    if errors:
        return errors

    errors.extend(validate_common_fields(path, data))

    return errors


def validate_file(path: Path):
    try:
        data = load_yaml(path)
    except Exception as exc:
        return [f"{path}: YAML parse error: {exc}"], None

    if not isinstance(data, dict):
        return [f"{path}: root YAML object must be a dictionary"], None

    deprecated = is_deprecated_rule(path, data)

    if deprecated:
        return validate_deprecated_rule(path, data), data

    return validate_active_rule(path, data), data


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
        errors, data = validate_file(path)
        all_errors.extend(errors)

        if isinstance(data, dict):
            deprecated = is_deprecated_rule(path, data)
            if not deprecated:
                rule_id = str(data.get("id", "")).strip()
                title = str(data.get("title", "")).strip().lower()

                if rule_id:
                    seen_ids.setdefault(rule_id, []).append(str(path))
                if title:
                    seen_titles.setdefault(title, []).append(str(path))

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