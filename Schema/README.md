# Schema

This folder contains simple JSON Schema files for the core domain objects in the `Access` repository.

Included schemas:
- `access-level.schema.json`
- `keycard.schema.json`
- `gate-schedule.schema.json`
- `access-gate.schema.json`
- `access-decision.schema.json`
- `access-log-entry.schema.json`
- `security-alert.schema.json`
- `index.json`

Notes:
- Access levels are represented as strings: `VISITOR`, `STAFF`, `MANAGER`, `ADMIN`.
- Dates use ISO format like `2026-04-12`.
- Datetimes use ISO 8601 strings.
- Schedule times use facility-local wall-clock values such as `08:00` or `18:30`.
