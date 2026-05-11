# Architecture Decision Record
## App 16 — Access
**Vault OS Group | Document 1 of 5**
**Status: Accepted**

---

## Context

The Access app is the Day 16 Vault OS module responsible for simulating a secure facility keycard and gate-access system. Its purpose is to model role-based authorization without turning the project into a real authentication system. The app needed to demonstrate object composition, encapsulated state, ordered permission levels, audit logging, and policy evaluation across multiple domain objects.

The domain has several independent concerns that must cooperate:

- a keycard identifies a person and stores lifecycle state;
- an access level defines authorization rank;
- a gate defines the minimum permission and optional schedule required for entry;
- an access log records every attempt for auditability;
- a suspicious activity monitor watches repeated denials;
- the CLI exposes the workflows through a learner-friendly menu.

The decision was to keep the system in a small flat module layout while treating the domain model seriously enough to show software design growth beyond simple CRUD or menu-driven scripting.

---

## Decisions

### Decision 1 — Use `IntEnum` for ranked access levels

**Chosen:** `AccessLevel` subclasses `IntEnum` with `VISITOR = 1`, `STAFF = 2`, `MANAGER = 3`, and `ADMIN = 4`.

**Rejected:** Plain strings, a normal `Enum`, or a separate dictionary mapping role names to numeric ranks.

**Reason:** Gate checks need to compare whether one level is greater than or equal to another. `IntEnum` makes this comparison explicit and readable:

```python
if keycard.access_level < self.required_access_level:
    deny
```

Using strings would require a separate ordering structure and would make authorization logic easier to break. A normal `Enum` would preserve names but not support rank comparisons without additional code. `IntEnum` is the right fit for a small educational RBAC simulation because it keeps the rank relationship close to the role definition.

---

### Decision 2 — Separate identity from authorization policy

**Chosen:** `Keycard` owns identity and lifecycle state; `AccessGate` owns the policy for a physical checkpoint; `AccessController` coordinates registry lookup, gate evaluation, logging, and suspicious-activity monitoring.

**Rejected:** A single object that both stores card data and decides whether the card can enter every location.

**Reason:** A keycard should not know the rules for every gate in a facility. The same card might be accepted at the lobby, denied at the control room, and denied after hours at the operations wing. Keeping gate rules inside `AccessGate` makes authorization contextual instead of hardcoded into the credential object.

This decision also demonstrates composition over inheritance: the controller composes a registry, gates, a log, and a monitor rather than relying on a deep class hierarchy.

---

### Decision 3 — Encapsulate keycard lifecycle behind methods

**Chosen:** `Keycard` uses private slot-backed attributes and exposes read-only properties. State changes go through methods such as `deactivate()`, `reactivate()`, `revoke()`, and `update_access_level()`.

**Rejected:** Public mutable attributes such as `card.active = False` or `card.revoked = True`.

**Reason:** Keycard state has rules. A revoked card cannot be reactivated. A revocation requires a reason. Expiry cannot be earlier than the issue date. Owner names cannot be blank. Allowing direct mutation would bypass those rules and create invalid objects.

The use of `__slots__` is also appropriate here because keycards are structured domain objects with a fixed field set. It prevents accidental attribute creation and reinforces the boundary between external callers and internal state.

---

### Decision 4 — Return structured decisions instead of raw booleans

**Chosen:** `AccessGate.check_access()` returns an immutable `AccessDecision` object containing `granted`, `reason`, `keycard_id`, `gate_name`, `timestamp`, and optional `warning`.

**Rejected:** Returning only `True` / `False`, printing directly from the domain layer, or raising exceptions for expected denials.

**Reason:** A denial is not necessarily an error. It may be a valid result: insufficient access level, expired card, deactivated card, revoked card, unknown card, or schedule violation. The caller needs both the verdict and the reason. Returning an immutable decision object gives the CLI and log layer a stable contract without requiring them to re-run policy logic.

Exceptions are still used for invalid system operations such as unknown gates or invalid object construction, but ordinary access denials remain data.

---

### Decision 5 — Normalize facility time at the domain boundary

**Chosen:** `naive_facility_moment()` converts all access timestamps into naive facility-local wall-clock datetimes. Naive datetimes pass through unchanged; aware datetimes are converted to the host system local zone and stripped of `tzinfo`.

**Rejected:** Mixing aware and naive datetimes directly inside schedule checks.

**Reason:** Gate schedules are expressed as local wall-clock `time` ranges, such as 08:00–18:00. Comparing those schedule windows to a mix of naive and timezone-aware datetimes would create inconsistent behavior and potential `TypeError` risks. Normalizing timestamps before schedule and expiry logic keeps the app predictable for its CLI-first use case.

The trade-off is that this is not a full multi-timezone facility model. It is a deliberately scoped local-time simulator.

---

### Decision 6 — Keep the audit log and suspicious monitor separate

**Chosen:** `AccessLog` records immutable attempt entries and alert entries. `SuspiciousActivityMonitor` independently observes denied attempts and emits `SecurityAlert` objects when a threshold is crossed.

**Rejected:** Putting suspicious-activity detection directly inside `AccessLog.record()`.

**Reason:** Logging and detection are related but distinct responsibilities. The log should store what happened. The monitor should interpret patterns. Keeping them separate allows different monitor thresholds or windows to be injected into `AccessController` without changing the log storage model.

This also keeps tests clearer: logging behavior can be validated independently from suspicious-activity detection.

---

### Decision 7 — Use a menu-driven CLI instead of flags/subcommands

**Chosen:** `VaultOSCLI` presents seven numbered menu options: issue a keycard, revoke a keycard, attempt a gate check, view the access log, view flagged cards, view active cards, and exit.

**Rejected:** A subcommand interface such as `vaultos-access issue --owner ... --level ...`.

**Reason:** This project is primarily about OOP, authorization policy, and state management, not command parsing. A menu loop keeps the user interaction simple and allows the app to demonstrate multiple workflows in one in-memory session. It also makes the demo state easier to explore manually: issue a card, attempt access, inspect logs, trigger suspicious activity, and view flagged cards without re-running separate commands.

---

## Consequences

**Positive:**
- `AccessLevel` comparisons make permission checks compact and readable.
- `Keycard` lifecycle rules are protected from direct external mutation.
- `AccessDecision`, `AccessLogEntry`, and `SecurityAlert` provide stable immutable records for audit-style behavior.
- `AccessController` cleanly coordinates registry, gate, logging, and monitoring without making any one class do everything.
- Menu workflows are easy to test with patched input and redirected stdout.
- The package metadata exposes a real console script, `vaultos-access`, which is a meaningful step beyond only running `python main.py`.

**Negative / Trade-offs:**
- All state is in memory. Issued cards, logs, and flagged cards disappear when the process exits.
- Schedule logic uses local wall-clock semantics rather than a true facility timezone setting.
- Duplicate suspicious-activity alerts are suppressed only for the life of the process.
- The menu CLI is convenient for learning but less scriptable than an argparse subcommand interface.
- `Keycard` is a regular class with private slots rather than a dataclass, so some boilerplate is necessary.

---

## Alternatives Not Explored

- **Persistent storage**: SQLite or JSON persistence would make the registry and logs survive restarts, but that would expand the project into file I/O and migration concerns beyond the Day 16 scope.
- **Password/authentication security**: This app simulates authorization policy, not secure identity verification. No real cryptographic keycard protocol is attempted.
- **External RBAC libraries**: Rejected because the learning target is implementing the policy model directly with Python classes.
- **Argparse command mode**: Useful for automation, but less aligned with the interactive facility simulator goal.

---

*Constitution reference: Article 1 (Python fundamentals and architecture), Article 3 (scope discipline), Article 4 (engineering quality), Article 6 (verification). No AI-authorship flags identified from the repository materials reviewed.*

---


# Technical Design Document
## App 16 — Access
**Vault OS Group | Document 2 of 5**

---

## Overview

Access is a Python CLI application that simulates keycard-based facility access control. It models issued credentials, ranked access levels, gates with minimum clearance rules, optional gate schedules, access decisions, audit logging, and suspicious denial detection.

**Primary files:**
- `access_control.py` — domain model and system orchestration
- `cli.py` — interactive menu interface
- `main.py` — script entry point
- `pyproject.toml` — packaging metadata and console script
- `tests/` — `unittest` coverage for domain and CLI behavior

**Runtime dependencies:** Python standard library only.

**Development dependencies:** optional `coverage[toml]`; editable install through `requirements.txt`.

---

## Purpose & Scope

The app demonstrates a role-based access control system for a secure facility. It is not a real security product. It does not persist state, authenticate real people, integrate with hardware, encrypt secrets, or communicate over a network.

This document covers the internal implementation of:

- access-level ranking;
- keycard lifecycle management;
- gate authorization checks;
- local facility time normalization;
- audit logging;
- suspicious repeated-denial detection;
- registry and controller orchestration;
- interactive CLI workflows.

---

## System Context

```
User terminal
    │
    ▼
vaultos-access / python main.py
    │
    ▼
cli.VaultOSCLI
    │
    ▼
AccessController
    ├── CardRegistry
    ├── AccessGate[]
    ├── AccessLog
    └── SuspiciousActivityMonitor
```

The application runs entirely in one local Python process. The CLI receives user input, delegates domain operations to `AccessController`, and prints results. No files are read or written during normal runtime. All cards, gates, logs, and alerts exist in memory.

---

## Module Dependency Graph

```text
main.py
└── cli.main
    └── VaultOSCLI
        └── access_control.AccessController
            ├── CardRegistry
            ├── AccessGate
            ├── AccessLog
            └── SuspiciousActivityMonitor
```

`access_control.py` has no dependency on `cli.py`. This is the correct direction: the domain layer can be tested and reused without the menu system.

`cli.py` imports `AccessController`, `AccessLevel`, and `build_demo_controller` from `access_control.py`.

`main.py` imports and calls `cli.main()`.

---

## Component Breakdown

### `naive_facility_moment(moment: datetime) -> datetime`
Normalizes timestamps into naive facility-local wall-clock datetimes. Naive values pass through unchanged. Aware values are converted through `moment.astimezone()` and then stripped of timezone metadata.

This helper centralizes the time policy used by gate schedules and keycard expiry checks.

---

### `AccessLevel(IntEnum)`
Defines four permission levels:

```python
VISITOR = 1
STAFF = 2
MANAGER = 3
ADMIN = 4
```

Because it subclasses `IntEnum`, levels can be compared with standard operators. `from_string()` supports case-insensitive CLI conversion and reports valid options when input is invalid.

---

### `Keycard`
Represents a credential issued to a person.

**Stored state:**
- card ID
- owner name
- access level
- issue date
- expiry date
- active flag
- revoked flag
- revocation reason
- revocation timestamp

`Keycard` uses `__slots__` and private attributes. External callers can inspect state through properties but must use methods to mutate lifecycle state.

**Lifecycle methods:**
- `update_access_level(new_level)`
- `deactivate()`
- `reactivate()`
- `revoke(reason, revoked_at=None)`
- `is_expired(when)`
- `status(when=None)`

**Status precedence:**

```text
REVOKED > EXPIRED > INACTIVE > ACTIVE
```

That means a revoked card reports `REVOKED` even if it would also be expired.

---

### `GateSchedule`
Frozen dataclass defining a start and end `time` window.

**Responsibilities:**
- reject zero-length schedules;
- support same-day windows, such as 08:00–18:00;
- support overnight windows, such as 22:00–06:00;
- expose a readable `label` property.

The schedule check is inclusive at both endpoints.

---

### `AccessGate`
Represents a physical checkpoint.

**Fields:**
- `name`
- `location`
- `required_access_level`
- optional `time_window`

`check_access(keycard, timestamp)` normalizes the timestamp, evaluates the card against policy, and returns an `AccessDecision`.

**Evaluation order:**

1. deny revoked cards;
2. deny deactivated cards;
3. deny expired cards;
4. deny insufficient access level;
5. deny outside the configured schedule;
6. grant access.

This ordering is important because it determines the reason shown to the user and recorded in the log.

---

### `AccessDecision`
Frozen dataclass returned by access checks.

```python
@dataclass(frozen=True, slots=True)
class AccessDecision:
    granted: bool
    reason: str
    keycard_id: str
    gate_name: str
    timestamp: datetime
    warning: str | None = None
```

`with_warning()` returns a new decision with the warning attached rather than mutating the existing decision.

---

### `AccessLogEntry`
Frozen dataclass stored for every access attempt.

```python
@dataclass(frozen=True, slots=True)
class AccessLogEntry:
    timestamp: datetime
    keycard_id: str
    gate_name: str
    granted: bool
    reason: str
```

The log record intentionally excludes the optional warning. Alerts are stored separately as `SecurityAlert` records.

---

### `SecurityAlert`
Frozen dataclass created by the suspicious activity monitor.

```python
@dataclass(frozen=True, slots=True)
class SecurityAlert:
    timestamp: datetime
    keycard_id: str
    denied_attempts: int
    window_minutes: int
    message: str
```

---

### `AccessLog`
In-memory append-only-style repository for attempts and alerts.

**Methods:**
- `record(decision)` — converts an `AccessDecision` into an `AccessLogEntry`
- `record_alert(alert)` — stores a `SecurityAlert`
- `entries()` — returns immutable tuple copy of attempt entries
- `alerts()` — returns immutable tuple copy of alerts
- `replace_stored_entries(entries, alerts)` — low-level restore hook

Although the app does not implement persistence, the restore hook makes the design ready for later file or database storage.

---

### `SuspiciousActivityMonitor`
Tracks repeated denied attempts by keycard ID.

**Internal structures:**

```python
_denials: dict[str, deque[datetime]]
_flagged_cards: dict[str, SecurityAlert]
```

The deque allows old denial timestamps to be removed efficiently from the left side of the queue as the sliding window advances.

Default behavior:
- threshold: 3 denials
- window: 10 minutes
- alert emitted once per keycard per process lifetime

---

### `CardRegistry`
Manages issued cards.

**Responsibilities:**
- issue new keycards with sequential IDs like `KC-0001`;
- look up cards by normalized ID;
- require a card or raise `KeyError`;
- revoke a card by ID;
- list active cards;
- list cards by access level;
- return all cards sorted by card ID;
- ingest restored cards for future persistence support.

---

### `AccessController`
Orchestrates the full access attempt workflow.

**Workflow for `attempt_access(card_id, gate_name, timestamp=None)`:**

1. normalize timestamp;
2. normalize card ID;
3. find the gate by case-insensitive name;
4. if the keycard is unknown, create a denied decision;
5. otherwise, delegate to `AccessGate.check_access()`;
6. record the decision in `AccessLog`;
7. pass the log entry to `SuspiciousActivityMonitor`;
8. if an alert is produced, store it and return a warning-enhanced decision.

---

### `build_demo_controller()`
Factory that creates a preloaded demonstration system.

**Demo cards:**
- Visitor
- Staff
- Manager
- Admin

**Demo gates:**
- Lobby Turnstile — VISITOR, always open
- Operations Wing — STAFF, 08:00–18:00
- Vault Antechamber — MANAGER, 06:00–22:00
- Control Room — ADMIN, always open

---

### `VaultOSCLI`
Interactive menu wrapper around `AccessController`.

**Menu options:**
1. Issue a keycard
2. Revoke a keycard
3. Attempt a gate check
4. View the access log
5. View flagged cards
6. View active cards
7. Exit

The CLI performs input validation, formats output, catches expected lookup and validation errors, and delegates the actual authorization behavior to the domain layer.

---

## Core Algorithms & Logic

### Access-level authorization

The access-rank check is a direct enum comparison:

```python
if keycard.access_level < gate.required_access_level:
    deny
```

This works because `AccessLevel` is an `IntEnum`.

---

### Gate schedule evaluation

Same-day window:

```text
start <= current_time <= end
```

Overnight window:

```text
current_time >= start OR current_time <= end
```

This allows schedules like 22:00–06:00 to span midnight without needing date-range objects.

---

### Suspicious activity detection

For every denied log entry:

1. append the timestamp to that card's deque;
2. compute cutoff as `entry.timestamp - window`;
3. remove old timestamps before the cutoff;
4. if the remaining count meets the threshold and the card has not already been flagged, emit a `SecurityAlert`.

Granted entries are ignored.

---

### Keycard ID generation

`CardRegistry` uses `itertools.count(starting_number)` and formats IDs as:

```python
KC-{number:04d}
```

This keeps generated IDs deterministic and easy to test.

---

## Data Structures

| Structure | Type | Purpose |
|---|---|---|
| `AccessLevel` | `IntEnum` | Ranked clearance values |
| `Keycard` | class with `__slots__` | Mutable credential lifecycle object |
| `GateSchedule` | frozen dataclass | Time-window policy |
| `AccessDecision` | frozen dataclass | Result of gate evaluation |
| `AccessLogEntry` | frozen dataclass | Audit record for one attempt |
| `SecurityAlert` | frozen dataclass | Suspicious-activity alert |
| `_cards` | `dict[str, Keycard]` | Registry lookup by card ID |
| `_gates` | `dict[str, AccessGate]` | Controller lookup by lowercase gate name |
| `_entries` | `list[AccessLogEntry]` | In-memory audit log |
| `_alerts` | `list[SecurityAlert]` | In-memory alert history |
| `_denials` | `defaultdict[str, deque[datetime]]` | Sliding window denial tracking |
| `_flagged_cards` | `dict[str, SecurityAlert]` | Duplicate-alert suppression |

---

## State Management

All state is in memory.

**Mutable process state includes:**
- issued keycards in `CardRegistry`;
- keycard lifecycle flags;
- access logs in `AccessLog`;
- security alerts in `AccessLog` and `SuspiciousActivityMonitor`;
- denial history queues in `SuspiciousActivityMonitor`.

There is no persistence layer. Restarting the program resets the demo controller, clears logs, and clears flagged-card memory.

---

## Error Handling Strategy

The app distinguishes invalid operations from expected access denials.

**Expected denials return `AccessDecision`:**
- unknown keycard;
- insufficient access level;
- expired keycard;
- revoked keycard;
- deactivated keycard;
- outside schedule.

**Invalid operations raise exceptions:**
- blank owner name;
- expiry before issue date;
- invalid access level string;
- blank gate name or location;
- unknown gate;
- unknown card when administrative revocation requires an existing card;
- revocation without a reason;
- duplicate revocation.

The CLI catches user-facing errors and prints readable messages rather than crashing.

---

## External Dependencies

Runtime uses only the Python standard library:

- `collections`
- `dataclasses`
- `datetime`
- `enum`
- `itertools`
- `unittest` for tests
- `io`, `contextlib`, and `unittest.mock` in CLI tests

Packaging uses `setuptools>=61` as the build backend. Optional development tooling includes `coverage[toml]>=7.6.0`.

---

## Concurrency Model

The app is entirely synchronous. There are no threads, async tasks, background jobs, or timers. Time-based rules are evaluated only when a method is called with a timestamp.

This is appropriate because the app is a CLI simulator, not a continuously running facility service.

---

## Known Limitations

- No persistence for cards, logs, or alerts.
- No true facility timezone configuration.
- No real authentication or hardware integration.
- No role-specific permissions beyond simple rank comparison.
- No gate-specific exception list.
- No CLI batch mode.
- No import/export format for logs.
- Suspicious activity state resets on restart.

---

## Design Patterns Used

### Composition
`AccessController` composes registry, gates, log, and monitor objects.

### Factory Function
`build_demo_controller()` creates a preconfigured system for CLI demonstration.

### Value Object / Record Pattern
`AccessDecision`, `AccessLogEntry`, `SecurityAlert`, and `GateSchedule` are immutable dataclass records.

### Registry Pattern
`CardRegistry` owns keycard issuance and lookup.

### Policy Object
`AccessGate` encapsulates entry policy for one physical location.

### Observer-like Monitor
`SuspiciousActivityMonitor.observe()` reacts to log entries without owning the logging system.

---


# Interface Design Specification
## App 16 — Access
**Vault OS Group | Document 3 of 5**

---

## Invocation Syntax

### Installed console command

```bash
vaultos-access
```

### Direct script entry

```bash
python main.py
```

Both start the same interactive menu.

---

## CLI Menu Contract

The CLI is interactive rather than flag-based. It repeatedly prints a menu and expects the user to enter a number or exit alias.

```text
Menu
1. Issue a keycard
2. Revoke a keycard
3. Attempt a gate check
4. View the access log
5. View flagged cards
6. View active cards
7. Exit
```

---

## Menu Option Reference

| Option | Name | Required Input | Output |
|---|---|---|---|
| `1` | Issue a keycard | owner name, access level, expiration days | issued card ID and expiry date |
| `2` | Revoke a keycard | card ID, revocation reason | revocation confirmation or error |
| `3` | Attempt gate check | gate number, card ID, timestamp | `GRANTED` or `DENIED` with reason; optional warning |
| `4` | View access log | none | formatted attempt records or empty message |
| `5` | View flagged cards | none | alert records or empty message |
| `6` | View active cards | none | active card list or empty message |
| `7` | Exit | none | shutdown message |
| `q` / `quit` / `exit` | Exit aliases | none | shutdown message |

---

## Input Contract

### Access levels

Accepted values are case-insensitive names:

```text
VISITOR
STAFF
MANAGER
ADMIN
```

Input is stripped and uppercased before conversion.

---

### Owner names

Owner names are stripped of surrounding whitespace. Blank owner names are rejected.

---

### Expiration days

The issue-card workflow accepts a whole number of days. Pressing Enter uses the default of `30` days. Negative values are rejected.

---

### Keycard IDs

CLI-entered keycard IDs are stripped and uppercased. Generated IDs follow this shape:

```text
KC-0001
KC-0002
KC-0003
```

---

### Timestamps

Gate checks accept either:

```text
YYYY-MM-DD HH:MM
```

or blank input, which means current system time.

The CLI treats typed timestamps as naive facility-local datetimes.

---

## Domain API Contract

### `AccessLevel.from_string(raw_value: str) -> AccessLevel`

Converts a string into one of the ranked enum values. Raises `ValueError` for unknown levels.

---

### `Keycard(...)`

```python
Keycard(
    card_id: str,
    owner_name: str,
    access_level: AccessLevel,
    issue_date: date,
    expiry_date: date,
)
```

**Validation:**
- owner name cannot be blank;
- expiry date cannot be earlier than issue date.

---

### `CardRegistry.issue_keycard(...) -> Keycard`

```python
issue_keycard(
    owner_name: str,
    access_level: AccessLevel,
    issue_date: date,
    expiry_date: date,
) -> Keycard
```

Generates a sequential card ID and stores the card in the registry.

---

### `AccessGate.check_access(keycard, timestamp) -> AccessDecision`

Returns a structured decision object. It does not print and does not log by itself.

---

### `AccessController.attempt_access(card_id, gate_name, timestamp=None) -> AccessDecision`

Full workflow entry point for gate attempts. It performs lookup, evaluates access, records a log entry, runs suspicious activity detection, and returns the final decision.

---

## Output Contract

### Successful card issue

```text
Issued KC-0005 to New Person (STAFF) through 2026-06-07.
```

### Successful access attempt

```text
GRANTED: Access granted.
```

### Denied access attempt

```text
DENIED: Insufficient access level. Requires ADMIN.
```

### Suspicious activity warning

```text
DENIED: Insufficient access level. Requires ADMIN.
WARNING: Suspicious activity detected: 3 denied attempts within 10 minutes.
```

### Access log format

```text
YYYY-MM-DD HH:MM:SS | KC-0001 | Lobby Turnstile | GRANTED | Access granted.
```

### Flagged cards format

```text
YYYY-MM-DD HH:MM:SS | KC-0001 | Suspicious activity detected: 3 denied attempts within 10 minutes.
```

---

## Exit Code Reference

The app does not explicitly return custom process exit codes. `main.py` calls `main()` without wrapping it in `SystemExit`. Under normal completion, Python exits with code `0`.

| Exit Code | Condition |
|---|---|
| `0` | Normal exit through option `7`, `q`, `quit`, `exit`, EOF, or KeyboardInterrupt |
| nonzero | Unhandled programmer error or environment failure outside normal CLI flow |

---

## Error Output Behavior

The app prints user-facing errors to stdout using `print()`. It does not write structured errors to stderr. Error messages are human-readable, not machine-readable.

Examples:

```text
Owner name is required.
Unknown option. Choose a number from the menu.
Please enter a whole number.
Please enter a non-negative number.
Timestamp must use the format YYYY-MM-DD HH:MM.
No keycard found for ID 'KC-9999'.
```

---

## Environment Variables

None.

---

## Configuration Files

None at runtime.

Packaging and tooling configuration live in `pyproject.toml`, but the application does not read runtime configuration files.

---

## Side Effects

Normal runtime side effects are limited to in-memory state mutation and console output.

**In-memory state changes include:**
- keycards issued;
- cards revoked;
- access attempts logged;
- security alerts recorded;
- suspicious card IDs remembered.

No runtime files are created, modified, or deleted.

---

## Usage Examples

### Basic use — start the app

```bash
vaultos-access
```

or:

```bash
python main.py
```

---

### Issue a staff keycard

```text
Select an option: 1
Owner name: New Person
Access level: STAFF
Expires in how many days? [30]:
Issued KC-0005 to New Person (STAFF) through 2026-06-07.
```

---

### Attempt access that should grant

```text
Select an option: 3
Choose a gate number: 1
Keycard ID: KC-0001
Timestamp for the attempt [press Enter for now, or use YYYY-MM-DD HH:MM]: 2026-06-01 12:00
GRANTED: Access granted.
```

---

### Attempt access that should deny

```text
Select an option: 3
Choose a gate number: 4
Keycard ID: KC-0001
Timestamp for the attempt [press Enter for now, or use YYYY-MM-DD HH:MM]: 2026-06-01 12:00
DENIED: Insufficient access level. Requires ADMIN.
```

---

### Intentional failure — invalid timestamp

```text
Select an option: 3
Choose a gate number: 1
Keycard ID: KC-0001
Timestamp for the attempt [press Enter for now, or use YYYY-MM-DD HH:MM]: not-a-date
Timestamp must use the format YYYY-MM-DD HH:MM.
```

---

### View access log

```text
Select an option: 4

Access Log
2026-06-01 12:00:00 | KC-0001 | Lobby Turnstile | GRANTED | Access granted.
```

---


# Runbook
## App 16 — Access
**Vault OS Group | Document 4 of 5**

---

## Prerequisites

- Python 3.10 or newer
- Local terminal / shell
- No third-party runtime dependencies
- `pip` for editable install

---

## Installation Procedure

### 1. Clone the repository

```bash
git clone https://github.com/PrincetonAfeez/Access.git
cd Access
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

macOS / Linux:

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install the project

```bash
pip install -r requirements.txt
```

This performs an editable install from the local folder. It also makes the console script available when the virtual environment's script directory is on the PATH.

---

## Configuration Steps

No runtime configuration is required.

The demo controller is built automatically when the CLI starts. It includes four sample keycards and four sample gates.

---

## Standard Operating Procedures

### Start the CLI

```bash
vaultos-access
```

Equivalent direct entry:

```bash
python main.py
```

---

### Exit safely

At the menu, enter any of:

```text
7
q
quit
exit
```

Ctrl+C and Ctrl+D are handled gracefully and print a shutdown message.

---

### Issue a keycard

1. Select option `1`.
2. Enter a nonblank owner name.
3. Enter an access level: `VISITOR`, `STAFF`, `MANAGER`, or `ADMIN`.
4. Enter expiration days or press Enter for 30 days.
5. Record the generated `KC-####` ID.

---

### Revoke a keycard

1. Select option `2`.
2. Review the issued card list printed by the CLI.
3. Enter the keycard ID.
4. Enter a nonblank revocation reason.
5. Confirm the revocation message.

Revocation is permanent for that keycard object.

---

### Attempt a gate check

1. Select option `3`.
2. Choose a gate number from the printed list.
3. Enter a keycard ID.
4. Enter a timestamp in `YYYY-MM-DD HH:MM` format, or press Enter for now.
5. Read the `GRANTED` or `DENIED` verdict and reason.

---

### View the access log

```text
Select an option: 4
```

The log shows every access attempt made during the current process.

---

### View flagged cards

```text
Select an option: 5
```

A card appears here only after suspicious activity detection emits an alert.

---

### View active cards

```text
Select an option: 6
```

The list excludes expired and deactivated cards. Revoked cards are inactive because revocation also sets the card's active flag to false.

---

## Health Checks

### Confirm import and package entry point

```bash
python -c "import access_control, cli; print('ok')"
```

Expected:

```text
ok
```

### Confirm CLI starts

```bash
vaultos-access
```

Expected startup header:

```text
Vault OS
Secure Facility Access Manager
```

Exit with `7`.

### Confirm tests are discoverable

```bash
python -m unittest discover -v -s tests -p "test*.py" -t .
```

Expected in a healthy checkout: all tests pass.

---

## Running Tests

```bash
python -m unittest discover -v -s tests -p "test*.py" -t .
```

The `-s tests` flag limits discovery to the test directory. The `-t .` flag keeps the project root on `sys.path` so `access_control` and `cli` import correctly.

---

## Optional Coverage Run

Install dev tooling:

```bash
pip install -e ".[dev]"
```

Run coverage:

```bash
python -m coverage run -m unittest discover -s tests -p "test*.py" -t .
python -m coverage report -m
```

The repo config enables branch coverage and reports missing lines for `access_control` and `cli`.

---

## Expected Output Samples

### Empty access log

```text
No access attempts recorded yet.
```

### Empty flagged cards

```text
No flagged cards.
```

### Active cards

```text
Active Cards
KC-0001 | Avery Stone | VISITOR | Expires 2026-06-21
```

### Denied scheduled access

```text
DENIED: Outside allowed access window for this gate (08:00 - 18:00).
```

### Revoked card denial

```text
DENIED: Keycard revoked: lost card
```

---

## Known Failure Modes

| Symptom | Probable Cause | Diagnostic Step | Resolution |
|---|---|---|---|
| `vaultos-access` not found | Editable install not active or venv not activated | Run `python -m pip show vaultos-access` | Activate venv and reinstall with `pip install -r requirements.txt` |
| `ModuleNotFoundError: access_control` | Running tests without project root on path | Check command flags | Use `python -m unittest discover -v -s tests -p "test*.py" -t .` |
| Invalid access level error | User typed unsupported role | Review accepted values | Use `VISITOR`, `STAFF`, `MANAGER`, or `ADMIN` |
| Timestamp rejected | Wrong format | Compare to prompt | Use `YYYY-MM-DD HH:MM` |
| Card not found | Mistyped or nonexistent card ID | View issued cards during revoke/check flow | Enter a generated `KC-####` ID |
| No flagged cards after denials | Threshold not reached or denials outside window | Review log timestamps | Repeat denied attempts within monitor window |
| Active cards list is empty | Cards are expired, deactivated, or revoked | Check all issued cards | Issue a new card with future expiry |

---

## Troubleshooting Decision Tree

```text
CLI will not start
├── Is virtual environment activated?
│   ├── No → activate .venv
│   └── Yes
├── Was editable install completed?
│   ├── No → pip install -r requirements.txt
│   └── Yes
└── Try direct entry: python main.py

Access attempt unexpectedly denied
├── Is the keycard ID correct?
├── Is the card expired?
├── Is the card revoked or deactivated?
├── Is the access level below the gate requirement?
└── Is the timestamp outside the gate schedule?

Suspicious activity not showing
├── Were the attempts denied, not granted?
├── Did the same keycard ID cause the denials?
├── Did the denials happen inside the time window?
└── Was the card already flagged earlier in this process?
```

---

## Dependency Failure Handling

There are no external runtime services. The most likely dependency problems are local Python packaging or test tooling issues.

For package setup issues:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

For coverage tooling issues:

```bash
pip install -e ".[dev]"
```

---

## Recovery Procedures

Because runtime state is in memory, the simplest recovery from inconsistent demo state is to exit and restart the CLI.

**To reset all cards, logs, and alerts:**

1. Exit the CLI with `7`.
2. Restart with `vaultos-access` or `python main.py`.

**To clear suspicious flags:** restart the process. The monitor suppresses duplicate alerts only in memory.

**To recover from accidental revocation in a demo session:** restart the process or issue a new keycard. Revoked card objects cannot be reactivated.

---

## Logging Reference

The app has an in-memory access log, not a file-based logger.

View current process log:

```text
Select an option: 4
```

Log record format:

```text
YYYY-MM-DD HH:MM:SS | KEYCARD_ID | GATE_NAME | GRANTED/DENIED | REASON
```

Security alerts are viewed separately:

```text
Select an option: 5
```

---

## Maintenance Notes

- Keep `AccessLevel` rank order stable; changing numeric values changes authorization behavior.
- If persistence is added later, carefully serialize `date`, `datetime`, enum values, revoked state, and alert history.
- If real facility timezone support is needed, replace host-local `astimezone()` behavior with explicit configured timezone handling.
- If CLI automation becomes important, add argparse subcommands rather than trying to script the menu loop.
- If suspicious activity policies grow, move monitor thresholds into configuration.

---


# Lessons Learned
## App 16 — Access
**Vault OS Group | Document 5 of 5**

---

## Project Summary

Access is a CLI-based keycard and permission manager for the Vault OS roadmap. It simulates a secure facility where keycards are issued to people, gates require minimum access levels, schedules can restrict when a gate is available, every access attempt is logged, and repeated denials can flag suspicious activity. The app achieved the main goal of moving from simple object methods into a coordinated domain model with identity, authorization, policy, audit records, and controller orchestration.

---

## Original Goals vs. Actual Outcome

The original goal was to build a role-based access control simulator using `AccessLevel`, `Keycard`, `AccessGate`, `AccessLog`, suspicious activity detection, a registry, and a CLI. The delivered app covers all of those core requirements.

The outcome is stronger than a basic menu CRUD app because the access decision itself is represented as structured data, not just printed text. The app also includes real packaging metadata and a console script, which makes it feel more operational than earlier one-file CLI exercises.

The main gap is persistence. The design includes restore-oriented hooks such as `replace_stored_entries()` and `ingest_restored_keycard()`, but the app does not actually save or load cards and logs. That omission is acceptable for the scope, but it is the clearest next architectural step.

---

## Technical Decisions That Paid Off

### `IntEnum` for access levels

Using `IntEnum` kept the permission model simple and readable. The code can compare roles directly without a helper function or lookup table. This makes the most important authorization rule easy to understand.

### Immutable records for decisions, logs, and alerts

Freezing `AccessDecision`, `AccessLogEntry`, and `SecurityAlert` prevents accidental mutation after an event has occurred. This is the right mental model for audit records: once recorded, the system should not casually rewrite history.

### Controller orchestration

`AccessController` is the right boundary for the full workflow. It keeps the CLI from needing to know how to look up cards, evaluate gates, record logs, and trigger alerts. The CLI asks for an attempt; the controller handles the system behavior.

### Sliding-window denial tracking

Using `deque` for denial timestamps is a strong fit. Suspicious activity detection needs to add new events and discard old ones efficiently. A normal list would work for tiny data, but `deque` better communicates the intended queue behavior.

### Packaging the app with a console script

Adding `vaultos-access` through `pyproject.toml` is a meaningful improvement. It shows awareness that a CLI app is not just a `.py` file; it can be installed and invoked as a command.

---

## Technical Decisions That Created Debt

### In-memory-only state

The app loses all issued cards, log entries, and flagged cards when the process exits. This is fine for a simulator, but it limits the realism of the access-control model. Audit logs are most valuable when they survive restarts.

### Host-local timezone normalization

`naive_facility_moment()` is practical, but it depends on the interpreter's local timezone for aware datetime conversion. A real facility system would need an explicit configured facility timezone rather than relying on the host environment.

### Menu-first interface

The menu is easy to use manually but not ideal for automation. A later version would benefit from `argparse` subcommands for issuing cards, listing logs, and attempting access in repeatable scripts.

### Revocation is permanent without a replacement workflow

The domain correctly treats revocation as permanent for one card object, but the CLI does not offer a clean "replace revoked card" workflow. Users can issue a new card manually, but the connection between old and replacement cards is not modeled.

---

## What Was Harder Than Expected

The hardest part was not comparing access levels; it was deciding where each responsibility belonged. It is tempting to let the CLI perform checks directly or to let `Keycard` decide where it can go. The better design required separating identity, policy, orchestration, and presentation.

The time-window logic also had more edge cases than it first appears to have. Same-day schedules and overnight schedules require different logic. Boundary behavior had to be intentional: this implementation treats start and end times as inclusive.

Suspicious activity detection introduced another subtle design problem: repeated alerts can become noisy. Suppressing duplicate alerts after the first threshold crossing was a good practical choice, even though the suppression is only in memory.

---

## What Was Easier Than Expected

The access-level hierarchy became simple once `IntEnum` was chosen. Without that decision, the app would need extra rank mapping logic. With it, the policy reads like plain English.

The audit log was also straightforward after `AccessDecision` was introduced. Instead of each caller constructing log messages differently, the log can consistently convert decisions into `AccessLogEntry` records.

Testing the CLI was manageable because the CLI methods print to stdout and use `input()`. `unittest.mock.patch` and `redirect_stdout` make it possible to simulate full menu flows without manual typing.

---

## Python-Specific Learnings

- `IntEnum` is a good fit when symbolic names also need ordering.
- Frozen dataclasses are useful for audit-style records.
- `slots=True` on dataclasses and `__slots__` on regular classes help define a fixed object shape.
- `deque` is more appropriate than a list for sliding-window queues.
- `itertools.count()` is a clean way to generate sequential IDs.
- `unittest.mock.patch` can turn an interactive CLI into testable code.
- `datetime.time` windows need explicit overnight handling.
- Naive and aware datetime values should not be mixed casually.

---

## Architecture Insights

The strongest architectural insight from this project is that authorization is a policy decision, not just an identity check. A card does not simply "have access" globally. It has a level, a status, and an expiry date; the gate has a requirement and possibly a time window; the controller provides the context for an attempt.

That separation makes the system easier to extend. Adding a new gate does not require changing `Keycard`. Adding persistence would not require changing `AccessGate`. Adding a different suspicious activity threshold does not require changing `AccessLog`.

The project also shows that a small CLI app can still have real domain boundaries. The code does not need a large framework to demonstrate architecture.

---

## Testing Gaps

The test suite covers a broad range of domain and CLI behavior: enum parsing, keycard validation, revocation, expiration, gate schedules, access decisions, logs, suspicious activity, controller injection, demo build, and menu flows.

Remaining gaps:

- no end-to-end installed command test for `vaultos-access` itself;
- no long-running session or large-log performance test;
- no persistence tests because persistence is not implemented;
- no property-based tests for many random schedule windows;
- no test for explicit configured facility timezone because none exists;
- no test for future import/export compatibility despite restore hooks.

These gaps are acceptable for the scope, but they identify the next level of maturity.

---

## Reusable Patterns Identified

### Decision object pattern

Returning a structured result instead of printing or returning a boolean is reusable across future CLI apps. It makes logic testable and presentation-independent.

### Registry + controller split

Keeping object storage in a registry and workflow orchestration in a controller is a useful pattern for future simulations.

### Immutable audit records

Any app that tracks history should consider frozen dataclass records. They reduce accidental mutation and make tests clearer.

### Sliding-window monitor

The denial-monitor pattern can be reused for rate limits, failed login attempts, repeated parser failures, or alert suppression.

### Demo factory

`build_demo_controller()` is a good pattern for creating a predictable CLI demo without hardcoding demo setup directly into the CLI class.

---

## If I Built This Again

The highest-impact change would be adding a persistence layer, probably JSON first and SQLite later. Cards, access logs, and security alerts are exactly the kind of data users expect to survive restarts.

The second highest-impact change would be adding an argparse command mode alongside the menu. The menu is good for exploration, but command mode would make the app easier to test from the shell and integrate into scripts.

---

## Open Questions

- Should facility timezone be configurable instead of using host-local conversion?
- Should suspicious activity alerts expire or remain indefinitely?
- Should a revoked card be replaceable with a linked replacement card ID?
- Should access policies support exceptions, such as a visitor card with one-time access to a normally restricted gate?
- Should audit logs be append-only once persistence exists?
- Should the CLI support exporting logs to CSV or JSON?

---

## Constitution Checklist

- **Article 1 — Python fundamentals and architecture:** Satisfied through classes, enums, dataclasses, controller orchestration, and explicit domain separation.
- **Article 3 — Scope discipline:** Satisfied. The app stays within a small-to-medium CLI simulator scope and does not overreach into real security or hardware integration.
- **Article 4 — Engineering quality:** Satisfied. Responsibilities are separated and core logic is testable without the CLI.
- **Article 5 — Trade-offs and constraints:** Satisfied through documented omissions: persistence, timezone configuration, and automation-friendly command mode.
- **Article 6 — Verification:** Satisfied through `unittest` tests covering domain and CLI behavior.
- **Article 8 — Final evaluation standard:** Valid learner project with clear growth in OOP, composition, policy modeling, and state handling.

---

*Constitution reference: This document satisfies Article 5 for App 16 and identifies the next refactors needed for long-term maintainability.*
