# winnow

Screen scanner findings against codified false-positive Insights.

A scanner produces candidates, not findings. Some match patterns already proven
to be false alarms. A port read as an exposure. A status code read as an identity.
An HTML page read as a JSON API. We write each of those lessons down as a NuClide
Insight, and winnow carries the Insights as code. It reads a scanner's output and
tags every candidate `PASS`, `REFUTED`, or `DOWNGRADE`. For each one it reports
the Insight that fired and a one-line reason, as text or JSON.

We used to keep those Insights as notes in a folder. Notes do not screen
anything, so the next scan repeated the same mistake and someone caught it again
from memory. winnow turns each note into a check that runs on every survey after
it.

## Install

```
git clone https://github.com/nuclide-research/winnow
cd winnow
python3 winnow.py <target>
```

Python 3.8+, standard library only, no dependencies. winnow is one script. It
carries a `#!/usr/bin/env python3` shebang, so `chmod +x winnow.py` then
`./winnow.py <target>` works too.

## Usage

```
python3 winnow.py menlohunt.json                # screen one scanner file
python3 winnow.py results/survey-2026-05/       # screen a directory tree
python3 winnow.py results/ --json --flagged     # JSON, only the flagged candidates
python3 winnow.py results/ --json --passed      # JSON, only the passing candidates
python3 winnow.py menlohunt.json --out report.txt
python3 winnow.py --version
```

The target is a single scanner JSON file or a directory. winnow walks a directory
tree for `*.json`, identifies each file by shape, and ignores anything it does not
recognize.

| Flag | Effect |
|------|--------|
| `--json` | emit JSON instead of the text report |
| `--flagged` | with `--json`, emit only the flagged (non-`PASS`) candidates |
| `--passed` | with `--json`, emit only the passing candidates |
| `--out FILE` | write the report to FILE instead of stdout |
| `--version` | print the version and exit |

## Input

winnow normalizes every scanner record into one flat candidate, so a signature
never has to know which scanner produced it:

```
scanner  host  port  check  severity  title  url  evidence
```

It reads two scanner shapes today:

- menlohunt JSON, recognized by a top-level `findings` and `summary`.
- aimap report JSON (v1.9+ flat schema), recognized by a top-level `enum_results`
  or `ports_scanned`.

winnow normalizes severity to one of `info`, `low`, `medium`, `high`, `critical`;
anything else becomes `medium`.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `PASS` | Not a known false alarm. Not verified; still needs a protocol check before it earns a finding label. |
| `REFUTED` | Not a real finding for this host. The exposure does not exist, or it exists but does not belong to this host. |
| `DOWNGRADE` | A real observation carrying a severity it did not earn. |

We keep `REFUTED` and `DOWNGRADE` apart on purpose. A refuted GCP metadata hit
names a service that is not there. A downgraded open port is real; it is just not
critical until something probes it.

## Signatures

v0.1.0 ships seven signatures: five `REFUTED`, two `DOWNGRADE`. Each one is a
codified Insight.

| Signature | Verdict | What it catches |
|-----------|---------|-----------------|
| `gcp-metadata-html` | REFUTED | menlohunt's `gcp_metadata` check firing on an HTML page; the GCP metadata API is link-local (169.254.169.254), Metadata-Flavor header-gated, serves plaintext or JSON, and is unreachable by an external scan |
| `metadata-endpoint-html` | REFUTED | the general case: any candidate naming a cloud metadata endpoint whose evidence is an HTML document; metadata endpoints return structured data |
| `firebase-name-from-hostname-label` | REFUTED | a `firebase_public` hit whose project name is a bare word taken from a host DNS label; the public database is real but belongs to an unrelated project, not this host |
| `gcs-name-from-hostname-label` | REFUTED | a `gcs_public` or `gcs_exists` hit whose bucket name is a bare word, with or without a `-dev`/`-prod`/`-data`/`-backup` suffix, taken from a DNS label; the bucket is real but is not this host's |
| `port-open-inflated` | DOWNGRADE | a menlohunt `port_open` reported at `low` or above; an open port earns no severity until a protocol probe runs, so it drops to `info` |
| `metabase-setup-token-null` | REFUTED | a Metabase setup hit where `/api/session/properties` returned 200 but the setup-token is null or empty; setup is already complete and the admin-claim surface is closed |
| `vllm-completions-405` | DOWNGRADE | vLLM present and unauthenticated but `/v1/completions` returned 405; the model is serving but completion is blocked, so it drops from `high` to `medium` pending a probe of `/v1/models` |

## Output

The default report groups flagged candidates by signature, largest group first.
It closes with a count of what was screened, refuted, downgraded, and passed.

With `--json`, winnow emits an array, one object per candidate. winnow attaches
the firing signature's id and reason; on a `PASS` both are null. JSON output omits
the candidate's `evidence`.

```json
{
  "verdict": "REFUTED",
  "insight": "gcp-metadata-html",
  "reason": "evidence is an HTML document; the GCP metadata API is link-local (169.254.169.254), gated by the Metadata-Flavor header, returns plaintext or JSON, and is unreachable by an external scan - it never produces an HTML body",
  "scanner": "menlohunt",
  "host": "198.51.100.7",
  "port": 443,
  "check": "gcp_metadata",
  "severity": "critical",
  "title": "GCP metadata API exposed",
  "url": "https://198.51.100.7/",
  "source_file": "results/menlohunt-survey.json"
}
```

## Example

Screening a directory holding one menlohunt file and one aimap report:

```
======================================================================
  winnow 0.1.0   8 candidates screened
======================================================================

FLAGGED  (matched a codified Insight)

  [port-open-inflated]  DOWNGRADE  -  5 candidates  (2 critical/high)
    insight: a port number names a candidate, not a finding
    reason : an open port is a real observation but carries no severity on its own; severity is earned by a protocol-level probe, so the candidate belongs at info until one is run
      - 192.0.2.10:80  high     Port 80/tcp open
      - 192.0.2.10:8080  medium   Port 8080/tcp open
      - 192.0.2.11:3000  high     Port 3000/tcp open
      - 192.0.2.12:9000  medium   Port 9000/tcp open
      ... and 1 more

  [gcp-metadata-html]  REFUTED  -  1 candidates  (1 critical/high)
    insight: GCP metadata API false positive
    reason : evidence is an HTML document; the GCP metadata API is link-local (169.254.169.254), gated by the Metadata-Flavor header, returns plaintext or JSON, and is unreachable by an external scan - it never produces an HTML body
      - 198.51.100.7:443  critical GCP metadata API exposed

----------------------------------------------------------------------
  screened        : 8
  false positives : 1   (1 critical/high - the exposure does not exist)
  over-rated      : 5   (2 critical/high - real, but no severity earned)
  passed          : 2   - not verified, still need protocol checks
----------------------------------------------------------------------
```

## Adding a signature

A signature is one entry in the `SIGNATURES` list: an `id`, a `verdict`, the
human-readable `insight`, a `match` function over a candidate, and a one-line
`reason`. winnow applies signatures in registry order and the first match wins.
Narrow signatures go before general ones; `gcp-metadata-html` sits ahead of
`metadata-endpoint-html` for that reason. A lesson learned once becomes a check
that runs on every survey after it.

## What winnow is not

winnow removes known noise. It does not verify. A passing candidate matched no
known false alarm. It still needs a protocol check. That check is the verification
stage, where a probe confirms the service is present and open. winnow holds no
state: no database, no dedup, no content addressing, one input in and one report
out.

## License

MIT. Part of the NuClide toolchain. Contact: [nuclide-research.com](https://nuclide-research.com)
