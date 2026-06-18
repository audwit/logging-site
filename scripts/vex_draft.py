#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Generate a draft CycloneDX 1.7 VDR file for a single CVE finding.

When --callgraph-metadata-dir and --vex-service-dir are both supplied the
script looks for root-cause analysis in callgraph-metadata and, if found,
runs vex-generation-service to produce an enriched draft with a reachability
verdict and pre-filled CVSS/CWE data.  Without that data it falls back to a
skeleton draft with TODO placeholders.

Usage (called once per CVE-component pair by the workflow):
    python scripts/vex_draft.py \
        --cve-id CVE-2025-12345 \
        --finding '{"cve_id":...,"dep_purl":...,"root_component":{...}}' \
        --vuln-dir src/vulnerabilities \
        [--callgraph-metadata-dir callgraph-metadata] \
        [--vex-service-dir vex-generation-service]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

UTC = timezone.utc

CDX_NS = "http://cyclonedx.org/schema/bom/1.7"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
SCHEMA_LOC = (
    "http://cyclonedx.org/schema/bom/1.7 "
    "https://cyclonedx.org/schema/bom-1.7.xsd"
)

_CPE_MAP = {
    "log4j-core":                 "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
    "log4j-1.2-api":              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
    "log4j-layout-template-json": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
    "log4net":                    "cpe:2.3:a:apache:log4net:*:*:*:*:*:*:*:*",
    "log4cxx":                    "cpe:2.3:a:apache:log4cxx:*:*:*:*:*:*:*:*",
}

_VERS_PREFIX = {
    "maven": "vers:maven",
    "nuget": "vers:nuget",
    "conan": "vers:semver",
}

# Maps vex-generation-service AnalysisState values → CycloneDX 1.7 state
_SERVICE_STATE_TO_CDX = {
    "unaffected": "not_affected",
    "affected":   "exploitable",
}
# Maps vex-generation-service Justification values → CycloneDX 1.7 justification
_SERVICE_JUSTIFICATION_TO_CDX = {
    "not_function_reachable": "code_not_reachable",
    "function_reachable":     "",  # no justification when exploitable
}


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _strip_version_from_purl(purl: str) -> str:
    return re.sub(r"@[^?#]+", "", purl)


def _bom_ref(root_component: dict) -> str:
    ref = root_component.get("bom-ref") or root_component.get("name", "unknown")
    if ref.startswith("pkg:"):
        base = re.sub(r"[@?#].*", "", ref)
        return base.rsplit("/", 1)[-1]
    return ref


def _purl_type(purl: str) -> str:
    m = re.match(r"pkg:([^/]+)/", purl)
    return m.group(1) if m else "maven"


def _vers_range(purl: str) -> str:
    prefix = _VERS_PREFIX.get(_purl_type(purl), "vers:generic")
    return f"{prefix}/>=0"


# ── Skeleton draft (no root-cause data available) ─────────────────────────────

def build_draft_xml(cve_id: str, root_component: dict, dep_purl: str) -> str:
    """Produce a skeleton CycloneDX 1.7 VDR with all fields as TODO placeholders."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = f"urn:uuid:{uuid.uuid4()}"
    bref = _bom_ref(root_component)

    comp_purl = _strip_version_from_purl(root_component.get("purl", ""))
    group = root_component.get("group", "")
    name = root_component.get("name", bref)
    cpe = _CPE_MAP.get(bref, "")

    group_line = f"      <group>{group}</group>\n" if group else ""
    cpe_line   = f"      <cpe>{cpe}</cpe>\n"      if cpe   else ""
    purl_line  = f"      <purl>{comp_purl}</purl>\n" if comp_purl else ""

    vers_range = _vers_range(dep_purl)

    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!--
  DRAFT — generated automatically by the VEX monitoring workflow.
  Maintainer checklist:
    [ ] Complete <description> and <recommendation>
    [ ] Add an <analysis> block (state / justification / detail)
    [ ] Set accurate version ranges in <affects>
    [ ] Fill in <ratings> (score / severity / vector) from NVD
    [ ] Add <credits> for the reporter
    [ ] Bump <updated> and <metadata/timestamp> whenever you edit this file
-->
<bom xmlns="{CDX_NS}"
     xmlns:xsi="{XSI_NS}"
     xsi:schemaLocation="{SCHEMA_LOC}"
     serialNumber="{serial}"
     version="1">

  <metadata>
    <timestamp>{now}</timestamp>
    <component type="library" bom-ref="{bref}">
{group_line}\
      <name>{name}</name>
{cpe_line}\
{purl_line}\
    </component>
    <manufacturer>
      <name>Apache Logging Services</name>
      <url>https://logging.apache.org</url>
    </manufacturer>
  </metadata>

  <vulnerabilities>
    <vulnerability>
      <id>{cve_id}</id>
      <source>
        <name>NVD</name>
        <url>https://nvd.nist.gov/vuln/detail/{cve_id}</url>
      </source>
      <ratings>
        <rating>
          <source>
            <name>NVD</name>
            <url>https://nvd.nist.gov/vuln/detail/{cve_id}</url>
          </source>
          <!-- TODO: fill in score, severity, method, vector from NVD -->
          <score>0.0</score>
          <severity>unknown</severity>
          <method>CVSSv3</method>
          <vector>TODO</vector>
        </rating>
      </ratings>
      <description><![CDATA[TODO: add description.]]></description>
      <recommendation><![CDATA[TODO: add recommendation / upgrade path.]]></recommendation>
      <!--
        TODO: add <analysis> block once the team has assessed impact, e.g.:
        <analysis>
          <state>not_affected</state>
          <justification>protected_by_mitigating_control</justification>
          <detail><![CDATA[Explain why.]]></detail>
        </analysis>
      -->
      <created>{now}</created>
      <published>{now}</published>
      <updated>{now}</updated>
      <credits>
        <!-- TODO: add reporter name/org -->
        <individuals>
          <individual>
            <name>TODO</name>
          </individual>
        </individuals>
      </credits>
      <affects>
        <target>
          <ref>{bref}</ref>
          <versions>
            <version>
              <!-- TODO: narrow this range once the fix version is known -->
              <range><![CDATA[{vers_range}]]></range>
            </version>
          </versions>
        </target>
      </affects>
    </vulnerability>
  </vulnerabilities>

</bom>
"""


# ── Enriched draft helpers ─────────────────────────────────────────────────────

def _cve_year_num(cve_id: str) -> tuple[str, str] | None:
    """'CVE-2025-48924' → ('2025', '48924'), or None if not parseable."""
    m = re.fullmatch(r"CVE-(\d{4})-(\d+)", cve_id)
    return (m.group(1), m.group(2)) if m else None


def _load_root_cause(metadata_dir: Path, cve_id: str) -> dict | None:
    """
    Load callgraph-metadata/vulnerabilities/<year>/<num>/root-cause.json.
    Returns the parsed dict, or None if the file does not exist.
    """
    parsed = _cve_year_num(cve_id)
    if not parsed:
        return None
    year, num = parsed
    rc_path = metadata_dir / "vulnerabilities" / year / num / "root-cause.json"
    if not rc_path.exists():
        return None
    try:
        return json.loads(rc_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"  WARNING: could not parse {rc_path}: {exc}", file=sys.stderr)
        return None


def _callgraph_path(metadata_dir: Path, purl: str) -> Path | None:
    """
    Resolve a purl to its callgraph.json inside callgraph-metadata/callgraphs/.

    Directory layout:  callgraphs/<group>/<artifact>/<version>/callgraph.json
    Tries the exact version from the purl first, then falls back to the
    highest available version directory.
    """
    m = re.match(r"pkg:maven/([^/]+)/([^@?#]+)(?:@([^?#]+))?", purl)
    if not m:
        return None
    group, artifact, version = m.group(1), m.group(2), m.group(3)
    base = metadata_dir / "callgraphs" / group / artifact
    if not base.exists():
        return None

    if version:
        exact = base / version / "callgraph.json"
        if exact.exists():
            return exact

    candidates = sorted(
        d / "callgraph.json"
        for d in base.iterdir()
        if d.is_dir() and (d / "callgraph.json").exists()
    )
    return candidates[-1] if candidates else None


def _flatten_root_cause_functions(entries: list) -> list[str]:
    """
    root-cause.json stores root_cause_functions as a list of objects:
        [{"package": "...", "methods": ["a.b.C.method", ...]}]
    The service expects a flat list of strings.
    """
    result: list[str] = []
    for entry in entries:
        if isinstance(entry, dict):
            result.extend(entry.get("methods", []))
        elif isinstance(entry, str):
            result.append(entry)
    return result


def _build_service_input(
    cve_id: str,
    dep_purl: str,
    root_component: dict,
    root_cause: dict,
    metadata_dir: Path,
) -> dict:
    """
    Assemble the input JSON for vex-generation-service.

    The dependency chain is a two-hop path:
        root Log4j artifact  →  vulnerable upstream dependency
    Callgraph paths are file:// URIs so analysis.py (curl) can read them
    from the already-checked-out callgraph-metadata tree.
    """
    root_purl = root_component.get("purl", "")

    chain: list[dict] = []
    root_cg = _callgraph_path(metadata_dir, root_purl)
    if root_cg:
        chain.append({"purl": root_purl, "callgraph": root_cg.resolve().as_uri()})

    dep_cg = _callgraph_path(metadata_dir, dep_purl)
    if dep_cg:
        chain.append({"purl": dep_purl, "callgraph": dep_cg.resolve().as_uri()})

    return {
        "cve_id": cve_id,
        "purl": _strip_version_from_purl(dep_purl),
        "root_cause_functions": _flatten_root_cause_functions(
            root_cause.get("root_cause_functions", [])
        ),
        "chains": [chain] if chain else [],
        "vex": root_cause.get("vex", {}),
    }


def _run_vex_service(service_dir: Path, input_data: dict) -> list | None:
    """
    Invoke vex-generation-service/main.py in a temp directory and return the
    parsed JSON output (a list-of-chains), or None on any failure.
    """
    with tempfile.TemporaryDirectory(prefix="vex_service_") as tmp:
        tmp_path = Path(tmp)
        input_file  = tmp_path / "input.json"
        output_file = tmp_path / "output.json"
        input_file.write_text(json.dumps(input_data, indent=2), encoding="utf-8")

        result = subprocess.run(
            [
                sys.executable,
                str(service_dir / "main.py"),
                "--input",  str(input_file),
                "--output", str(output_file),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            print(
                f"  WARNING: vex-generation-service exited {result.returncode}: "
                f"{result.stderr.strip()}",
                file=sys.stderr,
            )
            return None

        if not output_file.exists():
            print("  WARNING: vex-generation-service produced no output file.", file=sys.stderr)
            return None

        try:
            return json.loads(output_file.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(f"  WARNING: could not parse service output: {exc}", file=sys.stderr)
            return None


def _extract_analysis(service_output: list, root_purl: str) -> dict | None:
    """
    Walk the service output (list-of-chains of PackageToVex dicts) and return
    the first analysis dict found for the root component's purl, or None.
    """
    root_base = re.sub(r"[@?#].*", "", root_purl)
    for chain_results in service_output:
        for pkg_vex in chain_results:
            pkg_base = re.sub(r"[@?#].*", "", pkg_vex.get("purl", ""))
            if pkg_base != root_base:
                continue
            for vuln in pkg_vex.get("vex", {}).get("vulnerabilities", []):
                analysis = vuln.get("analysis")
                if analysis:
                    return analysis
    return None


# ── Enriched draft builder ─────────────────────────────────────────────────────

def build_enriched_xml(
    cve_id: str,
    root_component: dict,
    dep_purl: str,
    root_cause: dict,
    service_output: list,
) -> str:
    """
    Produce a CycloneDX 1.7 VDR XML enriched with:
      - CVSS ratings, description, CWEs from root-cause.json
      - <analysis> state/justification/detail from vex-generation-service
    Fields the maintainer still needs to complete:
      - <recommendation>, <credits>, version ranges in <affects>
    """
    now    = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = f"urn:uuid:{uuid.uuid4()}"
    bref   = _bom_ref(root_component)

    comp_purl = _strip_version_from_purl(root_component.get("purl", ""))
    group = root_component.get("group", "")
    name  = root_component.get("name", bref)
    cpe   = _CPE_MAP.get(bref, "")

    group_line = f"      <group>{group}</group>\n" if group else ""
    cpe_line   = f"      <cpe>{cpe}</cpe>\n"      if cpe   else ""
    purl_line  = f"      <purl>{comp_purl}</purl>\n" if comp_purl else ""

    # ── Ratings ───────────────────────────────────────────────────────────────
    vex_meta = root_cause.get("vex", {})
    ratings_blocks = []
    for r in vex_meta.get("ratings", []):
        score    = r.get("score", "0.0")
        severity = r.get("severity", "unknown")
        method   = r.get("method", "CVSSv3")
        vector   = r.get("vector", "TODO")
        ratings_blocks.append(f"""\
      <ratings>
        <rating>
          <source>
            <name>NVD</name>
            <url>https://nvd.nist.gov/vuln/detail/{cve_id}</url>
          </source>
          <score>{score}</score>
          <severity>{severity}</severity>
          <method>{method}</method>
          <vector>{vector}</vector>
        </rating>
      </ratings>""")
    ratings_xml = ("\n".join(ratings_blocks) + "\n") if ratings_blocks else (
        f"      <ratings>\n"
        f"        <rating>\n"
        f"          <source><name>NVD</name>"
        f"<url>https://nvd.nist.gov/vuln/detail/{cve_id}</url></source>\n"
        f"          <!-- TODO: fill in score, severity, method, vector from NVD -->\n"
        f"          <score>0.0</score><severity>unknown</severity>\n"
        f"          <method>CVSSv3</method><vector>TODO</vector>\n"
        f"        </rating>\n"
        f"      </ratings>\n"
    )

    # ── Description & recommendation ──────────────────────────────────────────
    description    = (vex_meta.get("description") or vex_meta.get("detail")
                      or "TODO: add description.")
    recommendation = vex_meta.get("recommendation") or "TODO: add recommendation / upgrade path."

    # ── CWEs ──────────────────────────────────────────────────────────────────
    cwes_xml = "".join(
        f"      <cwes><cwe>{cwe}</cwe></cwes>\n"
        for cwe in vex_meta.get("cwes", [])
    )

    # ── Analysis from service output ──────────────────────────────────────────
    root_purl = root_component.get("purl", "")
    analysis  = _extract_analysis(service_output, root_purl)

    if analysis:
        raw_state     = analysis.get("state", "")
        state         = _SERVICE_STATE_TO_CDX.get(raw_state, "in_triage")
        raw_just      = analysis.get("justification", "")
        justification = _SERVICE_JUSTIFICATION_TO_CDX.get(raw_just, "")
        # detail is a nested AnalysisDetail dict; the message is in explanations[0]
        detail_obj    = analysis.get("detail", {})
        if isinstance(detail_obj, dict):
            explanations = detail_obj.get("explanations", [])
            detail = explanations[0].get("message", "") if explanations else ""
        else:
            detail = str(detail_obj) if detail_obj else ""

        just_xml   = f"        <justification>{justification}</justification>\n" if justification else ""
        detail_xml = f"        <detail><![CDATA[{detail}]]></detail>\n"          if detail        else ""
        analysis_xml = (
            f"      <analysis>\n"
            f"        <state>{state}</state>\n"
            f"{just_xml}"
            f"{detail_xml}"
            f"      </analysis>\n"
        )
    else:
        analysis_xml = (
            "      <!--\n"
            "        TODO: add <analysis> block once the team has assessed impact, e.g.:\n"
            "        <analysis>\n"
            "          <state>not_affected</state>\n"
            "          <justification>code_not_reachable</justification>\n"
            "          <detail><![CDATA[Explain why.]]></detail>\n"
            "        </analysis>\n"
            "      -->\n"
        )

    # ── Timestamps ────────────────────────────────────────────────────────────
    created   = vex_meta.get("created",   now)
    published = vex_meta.get("published", now)
    vers_range = _vers_range(dep_purl)

    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!--
  ENRICHED DRAFT — generated by the VEX monitoring workflow with root-cause analysis.
  Pre-filled fields: CVSS ratings, description, CWEs, reachability analysis.
  Maintainer checklist:
    [ ] Verify the <analysis> verdict matches your own assessment
    [ ] Narrow version ranges in <affects> once the fix version is known
    [ ] Complete <recommendation> with the upgrade path
    [ ] Add <credits> for the reporter
    [ ] Bump <updated> and <metadata/timestamp> whenever you edit this file
-->
<bom xmlns="{CDX_NS}"
     xmlns:xsi="{XSI_NS}"
     xsi:schemaLocation="{SCHEMA_LOC}"
     serialNumber="{serial}"
     version="1">

  <metadata>
    <timestamp>{now}</timestamp>
    <component type="library" bom-ref="{bref}">
{group_line}\
      <name>{name}</name>
{cpe_line}\
{purl_line}\
    </component>
    <manufacturer>
      <name>Apache Logging Services</name>
      <url>https://logging.apache.org</url>
    </manufacturer>
  </metadata>

  <vulnerabilities>
    <vulnerability>
      <id>{cve_id}</id>
      <source>
        <name>NVD</name>
        <url>https://nvd.nist.gov/vuln/detail/{cve_id}</url>
      </source>
{ratings_xml}\
{cwes_xml}\
      <description><![CDATA[{description}]]></description>
      <recommendation><![CDATA[{recommendation}]]></recommendation>
{analysis_xml}\
      <created>{created}</created>
      <published>{published}</published>
      <updated>{now}</updated>
      <credits>
        <!-- TODO: add reporter name/org -->
        <individuals>
          <individual>
            <name>TODO</name>
          </individual>
        </individuals>
      </credits>
      <affects>
        <target>
          <ref>{bref}</ref>
          <versions>
            <version>
              <!-- TODO: narrow this range once the fix version is known -->
              <range><![CDATA[{vers_range}]]></range>
            </version>
          </versions>
        </target>
      </affects>
    </vulnerability>
  </vulnerabilities>

</bom>
"""


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve-id", required=True)
    parser.add_argument(
        "--finding",
        required=True,
        help="JSON-encoded finding dict (cve_id, dep_purl, root_component)",
    )
    parser.add_argument("--vuln-dir", required=True, type=Path)
    parser.add_argument(
        "--callgraph-metadata-dir",
        type=Path,
        default=None,
        help="Checked-out callgraph-metadata repo root (enables enriched draft)",
    )
    parser.add_argument(
        "--vex-service-dir",
        type=Path,
        default=None,
        help="Checked-out vex-generation-service repo root (enables enriched draft)",
    )
    args = parser.parse_args()

    finding       = json.loads(args.finding)
    cve_id        = finding["cve_id"]
    dep_purl      = finding["dep_purl"]
    root_component = finding["root_component"]

    bref     = _bom_ref(root_component)
    out_dir  = args.vuln_dir / cve_id
    out_file = out_dir / f"{bref}.cdx.xml"

    if out_file.exists():
        print(f"  SKIP: {out_file} already exists.")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)

    xml = None

    # ── Enriched path ─────────────────────────────────────────────────────────
    if args.callgraph_metadata_dir and args.vex_service_dir:
        root_cause = _load_root_cause(args.callgraph_metadata_dir, cve_id)
        if root_cause:
            print(f"  Root-cause data found for {cve_id} — running vex-generation-service …")
            svc_input  = _build_service_input(
                cve_id, dep_purl, root_component, root_cause, args.callgraph_metadata_dir
            )
            svc_output = _run_vex_service(args.vex_service_dir, svc_input)
            if svc_output is not None:
                xml = build_enriched_xml(
                    cve_id, root_component, dep_purl, root_cause, svc_output
                )
                print(f"  Enriched draft created for {cve_id}.")
            else:
                print(
                    f"  Service run failed for {cve_id} — falling back to skeleton.",
                    file=sys.stderr,
                )
        else:
            print(f"  No root-cause data for {cve_id} — using skeleton draft.")

    # ── Skeleton fallback ─────────────────────────────────────────────────────
    if xml is None:
        xml = build_draft_xml(cve_id, root_component, dep_purl)

    out_file.write_text(xml, encoding="utf-8")
    print(f"  Created: {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
