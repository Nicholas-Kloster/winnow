#!/usr/bin/env python3
"""
winnow - separate real findings from false-positive chaff.

A scanner produces candidates. Some of them match patterns already known to be
false alarms: a port number reported as an exposure, a status code read as an
identity, an HTML page mistaken for a JSON API. Each lesson gets written down
as a NuClide Insight. winnow carries those Insights as code and screens
scanner output against them.

Input  : a scanner's output - menlohunt JSON, an aimap report, or a directory
         tree of them.
Output : every candidate tagged PASS, REFUTED, or DOWNGRADE, with the Insight
         that flagged it and a one-line reason.

  PASS      not a known false alarm. NOT verified - still needs a protocol
            check before it earns a finding label.
  REFUTED   not a real finding for this host: the exposure does not exist,
            or it exists but does not belong to this host.
  DOWNGRADE a real observation carrying a severity it did not earn.

winnow removes known noise. It does not verify. That is the next stage.

Part of the NuClide toolchain.   github.com/nuclide-research/winnow
"""

import argparse
import glob
import json
import os
import re
import sys

__version__ = "0.1.0"

SEVERITIES = ("info", "low", "medium", "high", "critical")


def _norm_sev(s):
    s = (s or "").strip().lower()
    return s if s in SEVERITIES else "medium"


# --- candidate model --------------------------------------------------------
# A candidate is a normalized dict so signatures need not care which scanner
# produced it: scanner, host, port, check, severity, title, url, evidence.

def load_menlohunt(path):
    """menlohunt JSON -> candidates."""
    out = []
    try:
        d = json.load(open(path))
    except Exception:
        return out
    for f in d.get("findings", []):
        out.append({
            "scanner": "menlohunt",
            "host": f.get("host", d.get("target", "")),
            "port": f.get("port"),
            "check": f.get("check", ""),
            "severity": _norm_sev(f.get("severity")),
            "title": f.get("title", ""),
            "url": f.get("url", ""),
            "evidence": f.get("evidence", "") or "",
            "source_file": path,
        })
    return out


def load_aimap(path):
    """aimap report JSON (v1.9+ flat schema) -> candidates."""
    out = []
    try:
        d = json.load(open(path))
    except Exception:
        return out
    for e in d.get("enum_results", []):
        details = e.get("details")
        ev = "\n".join(details) if isinstance(details, list) else str(details or "")
        out.append({
            "scanner": "aimap",
            "host": e.get("host", ""),
            "port": e.get("port"),
            "check": (e.get("service", "") or "").lower(),
            "severity": _norm_sev(e.get("risk_level")),
            "title": e.get("service", ""),
            "url": e.get("base_url", ""),
            "evidence": ev,
            "source_file": path,
        })
    return out


def load_file(path):
    """Dispatch one JSON file to the right adapter by its shape."""
    try:
        d = json.load(open(path))
    except Exception:
        return []
    if not isinstance(d, dict):
        return []
    if "findings" in d and "summary" in d:
        return load_menlohunt(path)
    if "enum_results" in d or "ports_scanned" in d:
        return load_aimap(path)
    return []


def gather(target):
    """Accept a single file or a directory tree of scanner JSON."""
    if os.path.isdir(target):
        cands = []
        for path in sorted(glob.glob(os.path.join(target, "**", "*.json"),
                                     recursive=True)):
            cands += load_file(path)
        return cands
    if os.path.isfile(target):
        return load_file(target)
    sys.exit("winnow: no such file or directory: %s" % target)


# --- shared detectors -------------------------------------------------------

def looks_like_html(s):
    """True when a response body is an HTML document, not structured output."""
    if not s:
        return False
    head = s.lstrip()[:600].lower()
    return (head.startswith(("<!doctype", "<html"))
            or "<html" in head or "<head>" in head or "<body" in head)


_META_WORD = re.compile(r"\bmetadata\b", re.I)
_FIREBASE_HOST = re.compile(r"https?://([a-zA-Z0-9._-]+)\.firebaseio\.com", re.I)
_GCS_HOST = re.compile(r"storage\.googleapis\.com/([a-zA-Z0-9._-]+)", re.I)
_GCS_SUFFIX = re.compile(r"-(?:backup|dev|prod|data)$", re.I)


# --- the Insight registry ---------------------------------------------------
# Each signature is one codified NuClide Insight: a pattern already proven to
# be noise. A signature carries a verdict - REFUTED for a false positive,
# DOWNGRADE for a real observation that did not earn its severity. Adding the
# next Insight is one entry in this list.

def _sig_gcp_metadata_html(c):
    # The GCP metadata API lives at the link-local address 169.254.169.254,
    # is gated by the Metadata-Flavor: Google header, and returns plaintext
    # or JSON. It is not reachable by an external scan and never serves an
    # HTML document. menlohunt's gcp_metadata check fired on the target's own
    # web server returning an ordinary HTML page.
    return (c["scanner"] == "menlohunt"
            and c["check"] == "gcp_metadata"
            and looks_like_html(c["evidence"]))


def _sig_metadata_endpoint_html(c):
    # The generalized form: any cloud metadata endpoint (AWS, Azure, GCP)
    # returns structured data, never an HTML page.
    return bool(_META_WORD.search(c.get("title", "") or c.get("check", ""))
                and looks_like_html(c["evidence"]))


def _sig_firebase_name_from_label(c):
    # A Firebase finding whose project name is a bare generic word — earth,
    # marine, data — was guessed from one of the host's own DNS labels. A
    # bare word in the global firebaseio.com namespace belongs to an
    # unrelated project. The database is real and public, but it is not this
    # host's. The finding is a misattribution.
    if c["check"] != "firebase_public":
        return False
    m = _FIREBASE_HOST.search(c.get("url", ""))
    return bool(m and m.group(1).isalpha())


def _sig_gcs_name_from_label(c):
    # menlohunt's checkGCS guessed the bucket name from a host DNS label and
    # expanded it with -dev/-prod/-data/-backup. A bare generic word, with or
    # without one of those suffixes, collides with an unrelated bucket in the
    # global GCS namespace and is not the host's.
    if c["check"] not in ("gcs_public", "gcs_exists"):
        return False
    m = _GCS_HOST.search(c.get("url", ""))
    if not m:
        return False
    return _GCS_SUFFIX.sub("", m.group(1)).isalpha()


def _sig_port_open_inflated(c):
    # An open port carries no severity on its own. Severity is earned by a
    # protocol-level probe of the service, not by the port number.
    return (c["scanner"] == "menlohunt"
            and c["check"] == "port_open"
            and c["severity"] in ("low", "medium", "high", "critical"))


def _sig_metabase_setup_token_null(c):
    # /api/session/properties returning 200 does not mean the setup token is
    # live. If the response includes setup-token: null or setup-token: "" the
    # Metabase instance has already completed setup and the admin-claim surface
    # is closed. Scanners that anchor on the 200 status alone fire on every
    # deployed Metabase instance.
    ev = c.get("evidence", "") or ""
    return (
        "metabase" in (c.get("title", "") or c.get("check", "") or "").lower()
        and "setup" in (c.get("title", "") or c.get("check", "") or "").lower()
        and ("setup-token" in ev.lower() or "setup_token" in ev.lower())
        and ('"null"' in ev or ": null" in ev or '""' in ev
             or "null" in ev.lower())
    )


def _sig_vllm_completions_405(c):
    # vLLM is present and unauthenticated but /v1/completions returned 405
    # Method Not Allowed. The endpoint exists but completions are blocked at
    # the serving layer. The real enumeration surface is /v1/models; arbitrary
    # completion is not confirmed.
    ev = c.get("evidence", "") or ""
    service_field = (
        (c.get("title", "") or "")
        + " "
        + (c.get("check", "") or "")
        + " "
        + (c.get("url", "") or "")
    )
    return ("vllm" in service_field.lower() and "405" in ev)


SIGNATURES = [
    {
        "id": "gcp-metadata-html",
        "verdict": "REFUTED",
        "insight": "GCP metadata API false positive",
        "match": _sig_gcp_metadata_html,
        "reason": "evidence is an HTML document; the GCP metadata API is "
                  "link-local (169.254.169.254), gated by the Metadata-Flavor "
                  "header, returns plaintext or JSON, and is unreachable by an "
                  "external scan - it never produces an HTML body",
    },
    {
        "id": "metadata-endpoint-html",
        "verdict": "REFUTED",
        "insight": "cloud metadata endpoint claimed, HTML returned",
        "match": _sig_metadata_endpoint_html,
        "reason": "the finding claims a cloud metadata endpoint, but the "
                  "evidence is an HTML page; metadata endpoints return "
                  "structured data, never an HTML document",
    },
    {
        "id": "firebase-name-from-hostname-label",
        "verdict": "REFUTED",
        "insight": "Firebase project name guessed from a hostname label",
        "match": _sig_firebase_name_from_label,
        "reason": "the Firebase project name is a bare generic word taken "
                  "from one of the host's own DNS labels; a bare word in the "
                  "global firebaseio.com namespace belongs to an unrelated "
                  "project, so the public database is real but is not this "
                  "host's — a misattribution",
    },
    {
        "id": "gcs-name-from-hostname-label",
        "verdict": "REFUTED",
        "insight": "GCS bucket name guessed from a hostname label",
        "match": _sig_gcs_name_from_label,
        "reason": "the GCS bucket name is a bare generic word taken from one "
                  "of the host's DNS labels, optionally with a -dev/-prod/"
                  "-data/-backup suffix; a bare word in the global GCS "
                  "namespace belongs to an unrelated bucket, so the public "
                  "bucket is real but is not this host's — a misattribution",
    },
    {
        "id": "port-open-inflated",
        "verdict": "DOWNGRADE",
        "insight": "a port number names a candidate, not a finding",
        "match": _sig_port_open_inflated,
        "reason": "an open port is a real observation but carries no severity "
                  "on its own; severity is earned by a protocol-level probe, "
                  "so the candidate belongs at info until one is run",
    },
    {
        "id": "metabase-setup-token-null",
        "verdict": "REFUTED",
        "insight": "Metabase /api/session/properties returned 200 but "
                   "setup-token is null or empty — setup is complete",
        "match": _sig_metabase_setup_token_null,
        "reason": "the scanner found /api/session/properties returned 200 but "
                  "the setup-token field is null or empty; this means Metabase "
                  "setup has been completed and the admin-claim surface is "
                  "closed — not a finding",
    },
    {
        "id": "vllm-completions-405",
        "verdict": "DOWNGRADE",
        "insight": "vLLM /v1/completions returns HTTP 405 — OpenAI-compat API "
                   "present but completion endpoint blocked",
        "match": _sig_vllm_completions_405,
        "reason": "vLLM is present and unauthenticated but /v1/completions "
                  "returns 405 Method Not Allowed — the model is serving but "
                  "completions are blocked; the real risk is /v1/models (model "
                  "enumeration) and /v1/embeddings if enabled, not arbitrary "
                  "completion; downgrade from high to medium pending protocol "
                  "check",
    },
]


def screen(candidates):
    """Tag each candidate. First matching signature wins."""
    results = []
    for c in candidates:
        verdict, sig = "PASS", None
        for s in SIGNATURES:
            try:
                hit = s["match"](c)
            except Exception:
                hit = False
            if hit:
                verdict, sig = s["verdict"], s
                break
        results.append({"candidate": c, "verdict": verdict, "signature": sig})
    return results


# --- output -----------------------------------------------------------------

def _crit(group):
    return sum(1 for r in group
               if r["candidate"]["severity"] in ("critical", "high"))


def render(results):
    total = len(results)
    refuted = [r for r in results if r["verdict"] == "REFUTED"]
    downgraded = [r for r in results if r["verdict"] == "DOWNGRADE"]
    passed = [r for r in results if r["verdict"] == "PASS"]

    L = ["=" * 70,
         "  winnow %s   %d candidates screened" % (__version__, total),
         "=" * 70]

    by_sig = {}
    for r in refuted + downgraded:
        by_sig.setdefault(r["signature"]["id"], []).append(r)
    if by_sig:
        L.append("")
        L.append("FLAGGED  (matched a codified Insight)")
        for sid, group in sorted(by_sig.items(), key=lambda kv: -len(kv[1])):
            sig = group[0]["signature"]
            L.append("")
            L.append("  [%s]  %s  -  %d candidates  (%d critical/high)"
                     % (sid, sig["verdict"], len(group), _crit(group)))
            L.append("    insight: %s" % sig["insight"])
            L.append("    reason : %s" % sig["reason"])
            for r in group[:4]:
                c = r["candidate"]
                L.append("      - %s:%s  %-8s %s"
                         % (c["host"], c["port"] if c["port"] else "-",
                            c["severity"], (c["title"] or c["check"])[:46]))
            if len(group) > 4:
                L.append("      ... and %d more" % (len(group) - 4))

    L.append("")
    L.append("-" * 70)
    L.append("  screened        : %d" % total)
    L.append("  false positives : %d   (%d critical/high - the exposure does "
             "not exist)" % (len(refuted), _crit(refuted)))
    L.append("  over-rated      : %d   (%d critical/high - real, but no "
             "severity earned)" % (len(downgraded), _crit(downgraded)))
    L.append("  passed          : %d   - not verified, still need protocol "
             "checks" % len(passed))
    L.append("-" * 70)
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(
        prog="winnow",
        description="Screen scanner findings against codified NuClide Insights.")
    ap.add_argument("target", help="scanner JSON file, or a directory of them")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--flagged", action="store_true",
                    help="with --json, emit only flagged (non-PASS) candidates")
    ap.add_argument("--passed", action="store_true",
                    help="with --json, emit only the passing candidates")
    ap.add_argument("--out", metavar="FILE", help="write the report to FILE")
    ap.add_argument("--version", action="version", version="winnow " + __version__)
    args = ap.parse_args()

    results = screen(gather(args.target))

    if args.json:
        rows = results
        if args.flagged:
            rows = [r for r in results if r["verdict"] != "PASS"]
        elif args.passed:
            rows = [r for r in results if r["verdict"] == "PASS"]
        payload = [{
            "verdict": r["verdict"],
            "insight": r["signature"]["id"] if r["signature"] else None,
            "reason": r["signature"]["reason"] if r["signature"] else None,
            **{k: v for k, v in r["candidate"].items() if k != "evidence"},
        } for r in rows]
        text = json.dumps(payload, indent=2)
    else:
        text = render(results)

    if args.out:
        open(args.out, "w").write(text + "\n")
        sys.stderr.write("winnow: wrote %s\n" % args.out)
    else:
        print(text)


if __name__ == "__main__":
    main()
