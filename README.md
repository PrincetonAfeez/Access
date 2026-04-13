## Quick start

**Requirements:** Python 3.10 or newer.

```text
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
```

Run the CLI (after install, `vaultos-access` is on your PATH if the Scripts / `bin` directory is):

```text
vaultos-access
python main.py                  # equivalent entry
```

Run the test suite from this directory:

```text
python -m unittest discover -v -s tests -p "test*.py" -t .
```

**Project layout (high level):** `access_control.py` (domain), `cli.py` (menus), `main.py` (entry), `tests/` (unit tests), `pyproject.toml` (package metadata and tooling), `requirements.txt` (editable install), `.gitignore` (Python / venv / coverage artifacts).

Keycard & Permission Manager 
A CLI application that simulates a role-based access control system for a secure facility. The student builds an AccessLevel enum (VISITOR, STAFF, MANAGER, ADMIN), a Keycard class with identity and permission state, and an AccessGate class that evaluates whether a given keycard should be allowed through based on the gate’s requirements.
The core design lesson is composition over inheritance and the separation of identity from authorization. A keycard identifies a person, but what that person can access is determined by policy — their access level, whether the card is expired, whether the card has been revoked, and whether the gate has additional restrictions like time-of-day windows.
Features:
•	AccessLevel enum with VISITOR, STAFF, MANAGER, ADMIN and a clear rank ordering so levels can be compared with standard operators
•	Keycard class with unique ID, owner name, access level, issue date, expiry date, active vs administratively deactivated vs revoked status
•	Keycard state encapsulation — external code cannot directly flip flags; changes go through methods such as deactivate()/reactivate(), revoke(reason), and update_access_level()
•	AccessGate class that represents a physical entry point: it has a name, a location, a required minimum access level, and an optional time-of-day restriction (e.g., this gate only allows STAFF access between 8 AM and 6 PM)
•	check_access() method on the gate that takes a keycard and a timestamp, evaluates all conditions (level sufficient, card not expired, card not revoked, time-of-day valid), and returns a result object that includes whether access was granted and, if denied, the specific reason
•	AccessLog that records every check — timestamp, keycard ID, gate name, granted/denied, and reason — as immutable record objects (namedtuple or frozen dataclass)
•	Suspicious activity detection: after a configurable number of denied attempts by the same keycard within a time window, the system flags the card and logs a warning
•	CardRegistry that manages all keycards — issue new cards, look up cards by ID, revoke cards, list active cards, and list all cards for a given access level
•	CLI interface: issue a keycard, revoke a keycard, attempt a gate check, view the access log, view flagged cards, view active cards

Implementation notes (for integrators and students)

• **Facility time** — Gate schedules use naive `time` values as facility-local wall clock. Datetimes passed into `AccessGate.check_access` / `AccessController.attempt_access` are normalized with `access_control.naive_facility_moment`: naive values pass through; aware values convert to the host system’s local zone then drop tzinfo so schedule comparisons stay consistent. Other Vault OS days should use that helper when piping aware timestamps into this module.

• **Keycard lifecycle** — `Keycard.deactivate` / `Keycard.reactivate` temporarily block use without a revocation record. `Keycard.revoke` is permanent for that object. `Keycard.status` reports `INACTIVE` for deactivated (non-revoked) cards.

• **Suspicious activity** — After the first threshold crossing, a card id is remembered so repeated alerts are suppressed until the process restarts (in-memory registry).

## Merge checklist

Use this list before merging changes to this module (or run it in CI).

### Required

1. **Tests** — from this directory:

   ```text
   python -m unittest discover -v -s tests -p "test*.py" -t .
   ```

   `-s tests` limits discovery to `tests/`. `-t .` keeps the project root on `sys.path` so `access_control` and `cli` import correctly.

2. **Editable install** (confirms packaging metadata):

   ```text
   pip install -r requirements.txt
   ```

   (`pip install -e .` is equivalent.)

3. **Console entry point** (after install):

   ```text
   vaultos-access
   ```

   Confirm the menu appears and exit with option `7` (or `quit`).

### Recommended (quantitative)

4. **Coverage** — with dev dependencies:

   ```text
   pip install -e ".[dev]"
   python -m coverage run -m unittest discover -s tests -p "test*.py" -t .
   python -m coverage report -m
   ```

   Aim to keep branch coverage on `access_control.py` and `cli.py` from regressing when you touch policy or CLI flows. There is no fixed `fail_under` gate in this repo, so use local judgment.

### Manual spot-checks

5. Issue a keycard, run a gate check that should **grant**, then one that should **deny**, and confirm the access log shows both lines with sensible reasons.

6. Trigger **suspicious activity** (repeated denials for the same card) and confirm a warning appears and **flagged cards** lists the card once (duplicate alerts suppressed until restart).

Packaging

• **Install:** `pip install -r requirements.txt` (editable install from this folder; no extra runtime PyPI packages) or equivalently `pip install -e .`. Console entry point: `vaultos-access`.

• Automated tests live under `tests/`; run them from this directory using **Quick start** or the **Merge checklist** above.

• **Optional dev tooling:** same as step 4 in **Merge checklist** (`pip install -e ".[dev]"` plus `coverage run` / `coverage report`).
