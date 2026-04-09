from pathlib import Path
import sys
import yaml

DETECTIONS_ROOT = Path("detections/splunk")

# Full schema for active Splunk detections
REQUIRED_ACTIVE_FIELDS = [
    "title",
    "id",
    "source_id",
    "status",
    "description",
    "author",
    "date",
    "platform",
    "query_language",
    "logsource",
    "source_table",
    "search",
    "how_to_implement",
    "severity",
    "risk_score",
    "tactics",
    "techniques",
    "kill_chain_phases",
    "data_sources",
    "falsepositives",
]

# Lighter schema for deprecated Splunk detections
REQUIRED_DEPRECATED_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
]

ALLOWED_STATUS = {"experimental", "testing", "stable", "production", "deprecated"}
ALLOWED_SEVERITY = {"low", "medium", "high", "critical"}
ALLOWED_PLATFORM = {"splunk"}
ALLOWED_QUERY_LANGUAGE = {"spl"}

ID_PREFIX = "SPLK-"
SOURCE_ID_PREFIX = "SENT-"


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def is_deprecated_rule(path: Path, data: dict) -> bool:
    if "deprecated" in path.parts:
        return True
    lifecycle = str(data.get("lifecycle", "")).strip().lower()
    status = str(data.get("status", "")).strip().lower()
    return lifecycle == "deprecated" or status == "deprecated"


def validate_common_fields(path: Path, data: dict, deprecated: bool):
    errors = []

    title = str(data.get("title", "")).strip()
    rule_id = str(data.get("id", "")).strip()
    status = str(data.get("status", "")).strip().lower()

    if not title:
        errors.append(f"{path}: 'title' must not be empty")

    if not rule_id:
        errors.append(f"{path}: 'id' must not be empty")
    elif not deprecated and not rule_id.startswith(ID_PREFIX):
        errors.append(f"{path}: 'id' should start with '{ID_PREFIX}'")

    if status and status not in ALLOWED_STATUS:
        errors.append(
            f"{path}: invalid status '{data.get('status')}'. Allowed: {sorted(ALLOWED_STATUS)}"
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

    errors.extend(validate_common_fields(path, data, deprecated=False))

    platform = str(data.get("platform", "")).strip().lower()
    query_language = str(data.get("query_language", "")).strip().lower()
    severity = str(data.get("severity", "")).strip().lower()
    source_id = str(data.get("source_id", "")).strip()
    source_table = str(data.get("source_table", "")).strip()
    search = str(data.get("search", "")).strip()

    if platform not in ALLOWED_PLATFORM:
        errors.append(
            f"{path}: invalid platform '{data.get('platform')}'. Allowed: {sorted(ALLOWED_PLATFORM)}"
        )

    if query_language not in ALLOWED_QUERY_LANGUAGE:
        errors.append(
            f"{path}: invalid query_language '{data.get('query_language')}'. Allowed: {sorted(ALLOWED_QUERY_LANGUAGE)}"
        )

    if severity not in ALLOWED_SEVERITY:
        errors.append(
            f"{path}: invalid severity '{data.get('severity')}'. Allowed: {sorted(ALLOWED_SEVERITY)}"
        )

    if not source_id.startswith(SOURCE_ID_PREFIX):
        errors.append(f"{path}: 'source_id' should start with '{SOURCE_ID_PREFIX}'")

    if not source_table:
        errors.append(f"{path}: 'source_table' must not be empty")

    if not search:
        errors.append(f"{path}: 'search' must not be empty")

    risk_score = data.get("risk_score")
    if not isinstance(risk_score, int):
        errors.append(f"{path}: 'risk_score' must be an integer")
    elif not 0 <= risk_score <= 100:
        errors.append(f"{path}: 'risk_score' must be between 0 and 100")

    list_fields = [
        "how_to_implement",
        "tactics",
        "techniques",
        "kill_chain_phases",
        "data_sources",
        "falsepositives",
    ]

    for field in list_fields:
        if not isinstance(data.get(field), list):
            errors.append(f"{path}: '{field}' must be a list")

    # Optional but useful sanity checks
    if "modified" in data and data.get("modified") in (None, ""):
        errors.append(f"{path}: 'modified' is present but empty")

    return errors


def validate_deprecated_rule(path: Path, data: dict):
    errors = []

    for field in REQUIRED_DEPRECATED_FIELDS:
        if field not in data:
            errors.append(f"{path}: missing required field '{field}'")

    if errors:
        return errors

    errors.extend(validate_common_fields(path, data, deprecated=True))
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
        print("No Splunk detection YAML files found.")
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

    print(f"Validation successful. Checked {len(detection_files)} Splunk detection files.")


if __name__ == "__main__":
    main()