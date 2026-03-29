# logmask v1.0 — GitHub Project Setup
# Repository: radioastronomyio/logmask-python-library
# Run from any directory with gh CLI authenticated

$REPO = "radioastronomyio/logmask-python-library"

# ============================================================
# MILESTONES
# ============================================================

# Milestone 1: Data Integrity
gh api "repos/$REPO/milestones" --method POST `
  -f title="Data Integrity" `
  -f description="Fix correctness bugs in map generation and loading that break the 1:1 mapping guarantee. These are trust-level issues — if maps aren't correct, anonymization can't be trusted on real client data."

# Milestone 2: Privacy Leakage
gh api "repos/$REPO/milestones" --method POST `
  -f title="Privacy Leakage" `
  -f description="Fix cases where anonymized output still contains real infrastructure identifiers. Domain suffixes, TLDs, and internal naming conventions are leaking through the replacement engine."

# Milestone 3: Engine Hardening
gh api "repos/$REPO/milestones" --method POST `
  -f title="Engine Hardening" `
  -f description="Simplify and harden the replacement engine and configuration handling. These aren't broken per se, but they're more complex or fragile than they need to be."

# Milestone 4: Release Engineering
gh api "repos/$REPO/milestones" --method POST `
  -f title="Release Engineering" `
  -f description="CI, packaging metadata, documentation cleanup, and release process. No code logic changes — all additive or cosmetic."

# ============================================================
# ISSUES — Data Integrity
# ============================================================

gh issue create --repo $REPO `
  --title "Bug: IPv4 collision check validates against wrong set" `
  --label "bug" `
  --milestone "Data Integrity" `
  --body @"
## Problem

In ``map_engine.py``, the IPv4 fake address generator checks for collisions using ``fake_ip in merged_map``. But ``merged_map`` keys are **original** values, not anonymized values. This means the collision check is essentially a no-op — it's checking whether the generated fake IP happens to match a real IP, not whether it duplicates another fake IP already assigned.

This breaks the 1:1 mapping guarantee that the entire reveal workflow depends on. If two original IPs get the same fake IP, ``reveal_text()`` can only recover one of them.

## Where to Look

- ``map_engine.py`` — the ``_generate_fake_ipv4()`` method (or equivalent generation function)
- The loop that generates candidates and checks for uniqueness

## What Done Looks Like

- Generator maintains a set of **already-assigned anonymized values** and checks candidates against that set
- Generator also ensures ``fake != original`` (currently possible to generate identity mappings)
- Tests: generate 50+ fake IPs from overlapping /24 ranges and assert zero duplicates in the anonymized column
- Tests: assert no generated fake ever equals its original
"@

gh issue create --repo $REPO `
  --title "Bug: No uniqueness enforcement on anonymized values at write time" `
  --label "bug" `
  --milestone "Data Integrity" `
  --body @"
## Problem

``MapEngine`` writes mappings to CSV without verifying that the anonymized value column contains only unique entries. If any generation bug (like the IPv4 collision issue) produces duplicate anonymized values, they get persisted silently.

When ``reveal_text()`` inverts the map (original→anonymized becomes anonymized→original), duplicate anonymized values cause one mapping to silently overwrite the other in the dict. Data is lost with no error.

The architecture spec requires strict 1:1 bidirectional mapping. This is the enforcement gap.

## Where to Look

- ``map_engine.py`` — wherever mappings are written/appended to CSV
- The merge logic for project + global maps

## What Done Looks Like

- Write operations validate that no anonymized value already exists in the map before persisting
- If a duplicate is detected, raise an exception (fail closed, not fail open)
- Tests: attempt to write a map with duplicate anonymized values and assert it raises
- Tests: round-trip test — anonymize → write map → load map → reveal, verify perfect recovery
"@

gh issue create --repo $REPO `
  --title "Enhancement: Add map validate CLI command" `
  --label "enhancement" `
  --milestone "Data Integrity" `
  --body @"
## Problem

There is no way for an operator to verify map integrity before trusting it for anonymization or reveal. If a map file gets corrupted, has schema drift, or contains integrity violations, the tool will silently produce wrong output.

## Where to Look

- ``cli.py`` — add a new ``validate`` subcommand
- ``map_engine.py`` — add a ``validate_map()`` function the CLI calls

## What Done Looks Like

A ``logmask map validate`` (or ``logmask validate``) command that checks:

- No empty fields in any row
- No row where ``original == anonymized`` (identity mapping)
- No duplicate values in the anonymized column
- CSV schema matches expected columns (type, original, anonymized at minimum)
- Exit code 0 on pass, non-zero on any failure
- Human-readable output listing every violation found

Tests: create intentionally broken CSV files (empty fields, duplicates, schema mismatch, identity mappings) and assert the validator catches each one.
"@

gh issue create --repo $REPO `
  --title "Bug: Silent failure on CSV load errors (fail-open behavior)" `
  --label "bug" `
  --milestone "Data Integrity" `
  --body @"
## Problem

``_load_map_from_csv()`` wraps loading in a bare ``except`` that catches **any** exception, prints a message, and returns an empty dict ``{}``. This means:

- Corrupted CSV → tool runs with no map → copies files without replacing anything
- Schema change → same result
- Disk permission error → same result

The operator sees their files in the output directory and assumes anonymization happened. It didn't. This is a **fail-open** behavior in a security tool — the worst failure mode possible.

## Where to Look

- ``map_engine.py`` — ``_load_map_from_csv()`` and any other CSV loading paths

## What Done Looks Like

- Catch only specific, expected exceptions (e.g. ``FileNotFoundError`` for first-run when no map exists yet)
- For all other errors (parse failures, schema mismatches, permission errors), raise and halt
- First-run case (no map file yet) is handled gracefully — not an error, just an empty starting state
- Tests: corrupt a CSV in various ways and assert the loader raises instead of returning ``{}``
"@

# ============================================================
# ISSUES — Privacy Leakage
# ============================================================

gh issue create --repo $REPO `
  --title "Bug: FQDN anonymization leaks real domain suffix" `
  --label "bug" `
  --milestone "Privacy Leakage" `
  --body @"
## Problem

When anonymizing FQDNs, only the first label (hostname portion) is replaced. The real domain suffix passes through unchanged. For example:

``dc01.contoso.local`` → ``ANON-HOST.contoso.local``

This leaks the client's internal domain naming convention, which is exactly the kind of infrastructure fingerprint logmask exists to remove. The inline code comments already flag this as known domain leakage.

## Where to Look

- ``map_engine.py`` — the FQDN/hostname generation method
- The logic that splits the FQDN into labels and decides what to replace

## What Done Looks Like

- The entire FQDN is anonymized: all labels replaced, not just the first
- Label **count** is preserved (``a.b.c.local`` → ``x.y.z.example`` — same depth, different labels)
- Replacement suffixes come from a controlled list (e.g. the existing ``DOMAIN_NAMES`` allowlist) or are generated deterministically
- No real domain components survive in the output
- Tests: anonymize FQDNs of varying depth (2-label, 3-label, 4-label) and assert no original label appears in the result
"@

gh issue create --repo $REPO `
  --title "Bug: UPN anonymization leaks domain structure" `
  --label "bug" `
  --milestone "Privacy Leakage" `
  --body @"
## Problem

``_generate_fake_upn()`` preserves ``domain_parts[1]`` for dotted domains, leaking the TLD or internal domain suffix. It can also produce nonsense output for domains with more than two labels.

Same principle as the FQDN issue: the tool should preserve **structure** (that it's a UPN, that there's a domain with N parts) without preserving the **literal** domain components.

## Where to Look

- ``map_engine.py`` — ``_generate_fake_upn()``

## What Done Looks Like

- UPN domain portion is fully replaced (no original domain parts survive)
- Structure preserved: ``user@sub.domain.tld`` → ``fakeuser@fake.example.net`` (same label count)
- Handles domains with 1, 2, and 3+ labels correctly
- Tests: anonymize UPNs with varying domain depths and assert no original domain label appears in output
"@

# ============================================================
# ISSUES — Engine Hardening
# ============================================================

gh issue create --repo $REPO `
  --title "Enhancement: Switch replacement engine to iter_long()" `
  --label "enhancement" `
  --milestone "Engine Hardening" `
  --body @"
## Problem

``_apply_automaton()`` in ``replacer.py`` currently calls ``automaton.iter()`` to collect **all** matches, then manually filters to select the longest match at each position and remove overlaps. This works but it's reimplementing behavior that pyahocorasick already provides natively.

``pyahocorasick.Automaton.iter_long()`` returns only the longest match at each position — exactly the leftmost-longest semantics the architecture spec requires. Switching to it would:

- Reduce memory usage (no materialized match list)
- Simplify the code (remove the manual filtering logic)
- Reduce surface area for subtle overlap bugs

## Where to Look

- ``replacer.py`` — ``_apply_automaton()`` method
- pyahocorasick docs for ``iter_long()`` usage

## What Done Looks Like

- ``_apply_automaton()`` uses ``iter_long()`` instead of ``iter()`` + manual filtering
- The manual match-collection and overlap-filtering code is removed
- All existing replacer tests still pass (this is a refactor, not a behavior change)
- Add a specific test for the substring collision case: map contains both ``10.0.0.1`` and ``10.0.0.10``, text contains ``10.0.0.10``, assert only the longer match is replaced
"@

gh issue create --repo $REPO `
  --title "Bug: Config validation bypassed by CLI assignment" `
  --label "bug" `
  --milestone "Engine Hardening" `
  --body @"
## Problem

``Config.__post_init__()`` validates that file extensions start with ``"."``. But the CLI assigns ``config.extensions = args.ext`` **after** construction, completely bypassing that validation.

A user running ``logmask scan --ext log`` (missing the dot) would get no error — scanning would silently match nothing because the extension comparison fails.

## Where to Look

- ``cli.py`` — where ``config.extensions`` is assigned from args
- ``config.py`` (or wherever ``Config`` is defined) — the ``__post_init__`` validation

## What Done Looks Like

Pick one approach:

**Option A**: Make ``Config`` frozen (``frozen=True``) and provide a constructor like ``Config.with_extensions()`` that validates on creation. CLI uses the constructor instead of post-assignment.

**Option B**: Add a ``validate()`` method and call it after any mutation in the CLI.

Either way:
- ``--ext log`` raises a clear error telling the user to use ``--ext .log``
- Tests: construct or mutate a Config with invalid extensions and assert it raises
"@

# ============================================================
# ISSUES — Release Engineering
# ============================================================

gh issue create --repo $REPO `
  --title "Enhancement: Add GitHub Actions CI workflow" `
  --label "enhancement" `
  --milestone "Release Engineering" `
  --body @"
## Problem

No CI exists. Tests only run when someone remembers to run them locally. Regressions can be merged without anyone noticing.

## What Done Looks Like

A ``.github/workflows/ci.yml`` that:

- Triggers on push to main and on pull requests
- Runs ``pytest`` on at least Windows and Linux
- Uses Python version matrix (minimum: 3.10 and 3.12)
- Fails the workflow if any test fails
- Optionally reports coverage (not blocking, just informational)

Keep it simple — just pytest across the matrix. No linting or type checking gates in v1.0 unless it's trivial to add.
"@

gh issue create --repo $REPO `
  --title "Chore: Fix pyproject.toml metadata and entrypoint" `
  --label "chore" `
  --milestone "Release Engineering" `
  --body @"
## Problem

- ``project.urls`` points to a different/wrong repository name
- Console script entrypoint may not match the actual CLI entry function, meaning ``pip install`` + ``logmask`` command could behave differently than running ``python -m logmask``

These are small but they affect installability and first impressions.

## Where to Look

- ``pyproject.toml`` — ``[project.urls]`` section and ``[project.scripts]`` section

## What Done Looks Like

- All URLs point to ``radioastronomyio/logmask-python-library``
- Console script entrypoint calls the same function as ``__main__.py``
- Verify by running ``pip install -e .`` and confirming ``logmask --help`` works identically to ``python -m logmask --help``
"@

gh issue create --repo $REPO `
  --title "Chore: Replace template leftovers in SECURITY.md and CONTRIBUTING.md" `
  --label "chore" `
  --milestone "Release Engineering" `
  --body @"
## Problem

``SECURITY.md`` and ``CONTRIBUTING.md`` still contain references to "Docker Compose Cookbook" from the template they were copied from. This undermines trust and confuses anyone who looks at the repo.

## What Done Looks Like

- Both files reference logmask, not any other project
- Content is appropriate for a Python library (not a Docker project)
- Keep them short and practical — this is an internal MSP tool, not a massive open source project
- SECURITY.md should prominently note that **map files are sensitive artifacts** and must not be shared or committed
"@

gh issue create --repo $REPO `
  --title "Enhancement: Add CHANGELOG.md" `
  --label "enhancement" `
  --milestone "Release Engineering" `
  --body @"
## Problem

No changelog exists. For a v1.0 release, there should be a record of what shipped and what changed.

## What Done Looks Like

- ``CHANGELOG.md`` in repo root following Keep a Changelog format (https://keepachangelog.com)
- SemVer versioning (https://semver.org)
- Entry for v1.0.0 summarizing the initial release capabilities
- Entry for v0.x (current state) noting the pre-release development history at a high level — doesn't need to be exhaustive, just enough to show the project existed before v1.0
"@

Write-Host ""
Write-Host "Done. Created 4 milestones and 12 issues."
Write-Host "Verify at: https://github.com/$REPO/issues"