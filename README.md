# winnow

Separate real findings from false-positive chaff. Scanner output in, a
screened list out.

A scanner produces candidates. Some of them match patterns already known to be
false alarms: a port number reported as an exposure, a status code read as an
identity, an HTML page mistaken for a JSON API. Every time one is caught, the
lesson gets written down as a NuClide Insight.

The trouble is the Insights are notes in a folder. They do not screen
anything. The next scan repeats the exact mistake and a person has to catch it
again from memory.

winnow carries the Insights as code. It reads a scanner's output and screens
every candidate against them.

## Install

```
git clone https://github.com/nuclide-research/winnow
```

Python 3.8+. No dependencies. winnow is pure standard library.

## Usage

```
winnow menlohunt.json                 # screen one scanner file
winnow results/survey-2026-05/        # screen a whole directory tree
winnow results/ --json --flagged      # JSON, only the flagged candidates
winnow menlohunt.json --out report.txt
```

Input is a scanner's output: menlohunt JSON, an aimap report, or a directory
tree containing them. winnow finds the scanner files by shape and ignores the
rest.

## Verdicts

Every candidate is tagged one of three ways.

| Verdict | Meaning |
|---------|---------|
| `PASS` | Not a known false alarm. **Not verified** - still needs a protocol check before it earns a finding label. |
| `REFUTED` | A false positive. The exposure does not exist. |
| `DOWNGRADE` | A real observation carrying a severity it did not earn. |

`REFUTED` and `DOWNGRADE` are different on purpose. A refuted GCP metadata
finding describes a service that is not there. A downgraded open port is real,
it just is not critical until something probes it.

## Example

```
======================================================================
  winnow 0.1.0   7371 candidates screened
======================================================================

FLAGGED  (matched a codified Insight)

  [port-open-inflated]  DOWNGRADE  -  1442 candidates  (695 critical/high)
    insight: a port number names a candidate, not a finding
    reason : an open port is a real observation but carries no severity ...

  [gcp-metadata-html]  REFUTED  -  151 candidates  (113 critical/high)
    insight: GCP metadata API false positive
    reason : evidence is an HTML document; the GCP metadata API is ...

----------------------------------------------------------------------
  screened        : 7371
  false positives : 151    (113 critical/high - the exposure does not exist)
  over-rated      : 1442   (695 critical/high - real, but no severity earned)
  passed          : 5778   - not verified, still need protocol checks
----------------------------------------------------------------------
```

## The Insight registry

Each signature in winnow is one codified Insight. A signature is a match
function, a verdict, and a reason:

```python
{
    "id": "gcp-metadata-html",
    "verdict": "REFUTED",
    "insight": "GCP metadata API false positive",
    "match": _sig_gcp_metadata_html,
    "reason": "evidence is an HTML document; the GCP metadata API is "
              "link-local, header-gated, and never returns HTML",
}
```

Adding the next Insight is one entry in the `SIGNATURES` list. That is the
whole design: a lesson learned once becomes a check that runs forever.

v0.1 ships three signatures, drawn from verified false-positive classes:

- `gcp-metadata-html` - menlohunt reads an ordinary HTML page as the GCP
  metadata API. The metadata API is link-local, header-gated, and serves
  plaintext or JSON. Verified at 147 of 147 hits on a recent survey.
- `metadata-endpoint-html` - the generalized form for AWS and Azure metadata.
- `port-open-inflated` - an open port reported with an earned-looking severity.

## What winnow is not

winnow removes known noise. It does not verify. A candidate that passes winnow
is "not a known false alarm" - it is not "confirmed real". Passing candidates
go to the verification stage, where a protocol-level probe confirms the
service is there and open.

## License

MIT. Part of the NuClide toolchain.
