#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# python3 ./run_rm_java_cwe_lines.py \
#   --cwe 022 \
#   --csv ./repos/repos_java.csv \
#   --projects-dir ./projects \
#   --output-dir ./rm_output_java \
#   --global-prompt-max-lines 100

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import unquote

CODEQL_BIN = "codeql"
CODEQL_LANG = "java"
DEFAULT_CODEQL_CWE_ROOT = Path("/tmp/share/codeql/qlpacks/codeql/java-queries/1.6.3/Security/CWE")

CODEQL_SUPPORTED_CWES = [
    "022", "078", "079", "113", "117",
    "326", "327", "329", "347",
    "502", "643", "918", "1333",
]

SEMGREP_RULES: Dict[str, List[str]] = {
    "022": [
        "r/gitlab.find_sec_bugs.PATH_TRAVERSAL_IN-1",
        "r/gitlab.find_sec_bugs.PATH_TRAVERSAL_OUT-1.PATH_TRAVERSAL_OUT-1",
        "r/java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal",
        "r/java.micronaut.path-traversal.file-access-taint-msg.file-access-taint-msg",
        "r/java.micronaut.path-traversal.file-access-taint-sls.file-access-taint-sls",
        "r/java.micronaut.path-traversal.file-access-taint-ws.file-access-taint-ws",
        "r/java.micronaut.path-traversal.file-access-taint.file-access-taint",
        "r/java.micronaut.path-traversal.file-taint-msg.file-taint-msg",
        "r/java.micronaut.path-traversal.file-taint-sls.file-taint-sls",
        "r/java.micronaut.path-traversal.file-taint-ws.file-taint-ws",
        "r/java.micronaut.path-traversal.file-taint.file-taint",
        "r/java.servlets.security.httpservlet-path-traversal-deepsemgrep.httpservlet-path-traversal-deepsemgrep",
        "r/java.servlets.security.httpservlet-path-traversal.httpservlet-path-traversal",
        "r/java.spring.spring-tainted-path-traversal.spring-tainted-path-traversal",
    ],
    "078": [
        "r/java.lang.security.audit.command-injection-formatted-runtime-call.command-injection-formatted-runtime-call",
        "r/java.lang.security.audit.command-injection-process-builder.command-injection-process-builder",
        "r/java.lang.security.audit.tainted-cmd-from-http-request.tainted-cmd-from-http-request",
        "r/java.micronaut.command-injection.tainted-system-command-msg.tainted-system-command-msg",
        "r/java.micronaut.command-injection.tainted-system-command-sls.tainted-system-command-sls",
        "r/java.micronaut.command-injection.tainted-system-command-ws.tainted-system-command-ws",
        "r/java.micronaut.command-injection.tainted-system-command.tainted-system-command",
        "r/java.servlets.security.tainted-cmd-from-http-request-deepsemgrep.tainted-cmd-from-http-request-deepsemgrep",
        "r/java.servlets.security.tainted-cmd-from-http-request.tainted-cmd-from-http-request",
        "r/java.spring.command-injection.tainted-system-command.tainted-system-command",
        "r/java.spring.security.injection.tainted-system-command.tainted-system-command",
        "r/java.spring.simple-command-injection-direct-input.simple-command-injection-direct-input",
        "r/mobsf.mobsfscan.injection.command_injection.command_injection",
    ],
    "079": [
        "r/java.lang.security.servletresponse-writer-xss.servletresponse-writer-xss",
        "r/java.servlets.security.servletresponse-writer-xss.servletresponse-writer-xss",
        "r/java.spring.security.injection.tainted-html-string.tainted-html-string",
    ],
    "326": ["r/mobsf.mobsfscan.crypto.weak_key_size.weak_key_size"],
    "327": [
        "r/gitlab.find_sec_bugs.CIPHER_INTEGRITY-1",
        "r/gitlab.find_sec_bugs.ECB_MODE-1",
        "r/gitlab.find_sec_bugs.PADDING_ORACLE-1",
        "r/java.java-jwt.security.jwt-none-alg.java-jwt-none-alg",
        "r/java.jjwt.security.jwt-none-alg.jjwt-none-alg",
        "r/mobsf.mobsfscan.crypto.aes_ecb.aes_ecb_mode",
        "r/mobsf.mobsfscan.crypto.aes_ecb.aes_ecb_mode_default",
        "r/mobsf.mobsfscan.crypto.insecure_ssl_v3.insecure_sslv3",
        "r/mobsf.mobsfscan.crypto.weak_ciphers.weak_cipher",
    ],
    "329": ["r/mobsf.mobsfscan.crypto.cbc_static_iv.cbc_static_iv"],
    "502": [
        "r/java.lang.audit.classloader-object-deserialization.classloader-object-deserialization",
        "r/java.micronaut.deserialization.objectinputstream-deserialization-msg.objectinputstream-deserialization-msg",
        "r/java.micronaut.deserialization.objectinputstream-deserialization-sls.objectinputstream-deserialization-sls",
        "r/java.micronaut.deserialization.objectinputstream-deserialization-ws.objectinputstream-deserialization-ws",
        "r/java.micronaut.deserialization.objectinputstream-deserialization.objectinputstream-deserialization",
        "r/java.rmi.security.server-dangerous-object-deserialization.server-dangerous-object-deserialization",
        "r/java.servlets.security.castor-deserialization-deepsemgrep.castor-deserialization-deepsemgrep",
        "r/java.servlets.security.kryo-deserialization-deepsemgrep.kryo-deserialization-deepsemgrep",
        "r/java.servlets.security.objectinputstream-deserialization-servlets.objectinputstream-deserialization-servlets",
        "r/java.servlets.security.xstream-anytype-deserialization-deepsemgrep.xstream-anytype-deserialization-deepsemgrep",
        "r/java.spring.security.castor-deserialization-deepsemgrep.castor-deserialization-deepsemgrep",
        "r/java.spring.security.kryo-deserialization-deepsemgrep.kryo-deserialization-deepsemgrep",
        "r/java.spring.security.objectinputstream-deserialization-spring.objectinputstream-deserialization-spring",
        "r/java.spring.security.xstream-anytype-deserialization-deepsemgrep.xstream-anytype-deserialization-deepsemgrep",
        "r/mobsf.mobsfscan.deserialization.jackson_deserialization.jackson_deserialization",
    ],
    "918": [
        "r/gitlab.find_sec_bugs.URLCONNECTION_SSRF_FD-1",
        "r/java.ai.amazon.http.detect-amazon.detect-amazon",
        "r/java.ai.anthropic.http.detect-anthropic.detect-anthropic",
        "r/java.ai.cohere.http.detect-cohere.detect-cohere",
        "r/java.ai.deepseek.http.detect-deepseek.detect-deepseek",
        "r/java.ai.fireworks.http.detect-fireworks.detect-fireworks",
        "r/java.ai.google.http.detect-gemini.detect-gemini",
        "r/java.ai.google.http.detect-vertex.detect-vertex",
        "r/java.ai.huggingface.http.detect-huggingface.detect-huggingface",
        "r/java.ai.microsoft.http.detect-microsoft.detect-microsoft",
        "r/java.ai.mistral.http.detect-mistral.detect-mistral",
        "r/java.ai.openai.http.detect-openai.detect-openai",
        "r/java.ai.perplexity.http.detect-perplexity.detect-perplexity",
        "r/java.ai.replicate.http.detect-replicate.detect-replicate",
        "r/java.ai.together.http.detect-together.detect-together",
        "r/java.ai.xai.http.detect-xai.detect-xai",
        "r/java.micronaut.ssrf.httpclient-taint-concat-msg.httpclient-taint-concat-msg",
        "r/java.micronaut.ssrf.httpclient-taint-concat-sls.httpclient-taint-concat-sls",
        "r/java.micronaut.ssrf.httpclient-taint-concat-ws.httpclient-taint-concat-ws",
        "r/java.micronaut.ssrf.httpclient-taint-concat.httpclient-taint-concat",
        "r/java.micronaut.ssrf.httpclient-taint-msg.httpclient-taint-msg",
        "r/java.micronaut.ssrf.httpclient-taint-sls.httpclient-taint-sls",
        "r/java.micronaut.ssrf.httpclient-taint-ws.httpclient-taint-ws",
        "r/java.micronaut.ssrf.httpclient-taint.httpclient-taint",
        "r/java.micronaut.ssrf.java-http-concat-taint-msg.java-http-concat-taint-msg",
        "r/java.micronaut.ssrf.java-http-concat-taint-sls.java-http-concat-taint-sls",
        "r/java.micronaut.ssrf.java-http-concat-taint-ws.java-http-concat-taint-ws",
        "r/java.micronaut.ssrf.java-http-concat-taint.java-http-concat-taint",
        "r/java.micronaut.ssrf.java-http-taint-msg.java-http-taint-msg",
        "r/java.micronaut.ssrf.java-http-taint-sls.java-http-taint-sls",
        "r/java.micronaut.ssrf.java-http-taint-ws.java-http-taint-ws",
        "r/java.micronaut.ssrf.java-http-taint.java-http-taint",
        "r/java.servlets.security.tainted-ssrf-deepsemgrep-add.tainted-ssrf-deepsemgrep-add",
        "r/java.servlets.security.tainted-ssrf-deepsemgrep-format.tainted-ssrf-deepsemgrep-format",
        "r/java.servlets.security.tainted-ssrf-deepsemgrep.tainted-ssrf-deepsemgrep",
        "r/java.servlets.security.tainted-ssrf.tainted-ssrf",
        "r/java.spring.security.injection.tainted-url-host.tainted-url-host",
        "r/java.spring.security.tainted-ssrf-spring-add.tainted-ssrf-spring-add",
        "r/java.spring.security.tainted-ssrf-spring-format.tainted-ssrf-spring-format",
        "r/java.spring.ssrf.tainted-ssrf-spring.tainted-ssrf-spring",
    ],
}

SEMGREP_SUPPORTED_CWES = sorted(SEMGREP_RULES.keys())
SUPPORTED_CWES = sorted(set(CODEQL_SUPPORTED_CWES) | set(SEMGREP_SUPPORTED_CWES))


def normalize_cwe(cwe: str) -> str:
    digits = re.sub(r"(?i)cwe[-_\s]*|[^0-9]", "", str(cwe or "")).lstrip("0") or "0"
    if len(digits) <= 3:
        digits = digits.zfill(3)
    return digits


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())


def split_eol(line: str) -> Tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    if line.endswith("\r"):
        return line[:-1], "\r"
    return line, ""


def blank_full_lines(lines: List[str], start_line: int, end_line: int) -> None:
    total = len(lines)
    start_line = max(1, min(start_line, total))
    end_line = max(1, min(end_line, total))
    if end_line < start_line:
        start_line, end_line = end_line, start_line
    for line_no in range(start_line, end_line + 1):
        _, eol = split_eol(lines[line_no - 1])
        lines[line_no - 1] = eol


def merge_ranges(ranges: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    items = sorted((min(a, b), max(a, b)) for a, b in ranges)
    if not items:
        return []
    merged: List[List[int]] = [[items[0][0], items[0][1]]]
    for start, end in items[1:]:
        last = merged[-1]
        if start <= last[1] + 1:
            last[1] = max(last[1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for _ in handle)


def check_command(command: str) -> bool:
    try:
        proc = subprocess.run([command, "--version"], capture_output=True, text=True, timeout=5)
        return proc.returncode == 0
    except Exception:
        return False


def run_cmd(
    cmd: List[str],
    *,
    cwd: Optional[Path] = None,
    timeout_sec: Optional[int] = None,
) -> Tuple[int, float, str, str]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        return proc.returncode, time.perf_counter() - start, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        return 124, time.perf_counter() - start, exc.stdout or "", exc.stderr or f"timeout after {timeout_sec}s"


def norm_rel_path(path: str) -> str:
    if path is None:
        return ""
    value = str(path).strip()
    if not value:
        return ""
    if value.startswith("file://"):
        value = value[7:]
    value = unquote(value)
    value = value.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value


def resolve_codeql_cwe_root(override: Optional[str]) -> Optional[Path]:
    candidates: List[Path] = []
    if override:
        candidates.append(Path(override).expanduser())
    candidates.append(DEFAULT_CODEQL_CWE_ROOT)
    candidates.extend(sorted(Path.home().glob(".codeql/packages/codeql/java-queries/*/Security/CWE")))
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate.resolve()
    return None


def resolve_cwe_queries_from_dir(root: Path) -> List[str]:
    if not root.exists() or not root.is_dir():
        return []
    supported_nums = {int(x) for x in CODEQL_SUPPORTED_CWES}
    queries: List[str] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        match = re.match(r"(?i)^cwe-(\d+)$", child.name)
        if not match:
            continue
        if int(match.group(1)) not in supported_nums:
            continue
        for query in child.rglob("*.ql"):
            if query.is_file():
                queries.append(str(query.resolve()))
    return sorted(set(queries))


def parse_sarif_results(sarif_file: Path, target_cwe: str) -> List[Tuple[str, int, int]]:
    if not sarif_file.exists():
        return []
    target_cwe = normalize_cwe(target_cwe)
    cwe_int = int(target_cwe)
    needle_a = f"cwe-{target_cwe}".lower()
    needle_b = f"cwe-{cwe_int}".lower()
    data = json.loads(sarif_file.read_text(encoding="utf-8", errors="replace"))

    findings: List[Tuple[str, int, int]] = []
    for run in data.get("runs", []) or []:
        rules = {rule.get("id"): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []}
        for result in run.get("results", []) or []:
            rule_id = (result.get("ruleId") or "").strip()
            rule_info = rules.get(rule_id, {}) or {}
            tags = [str(tag).lower() for tag in (rule_info.get("properties", {}).get("tags", []) or [])]
            if not ((needle_a in rule_id.lower()) or (needle_b in rule_id.lower()) or any((needle_a in tag) or (needle_b in tag) for tag in tags)):
                continue
            locations = result.get("locations", []) or []
            if not locations:
                continue
            phys = locations[0].get("physicalLocation", {}) or {}
            rel_path = norm_rel_path(phys.get("artifactLocation", {}).get("uri", "") or "")
            if not rel_path:
                continue
            region = phys.get("region", {}) or {}
            start_line = int(region.get("startLine", 0) or 0)
            end_line = int(region.get("endLine", start_line) or start_line)
            if start_line > 0 and end_line > 0:
                findings.append((rel_path, start_line, end_line))
    return findings


def parse_semgrep_results(semgrep_json: Path) -> List[Tuple[str, int, int]]:
    if not semgrep_json.exists():
        return []
    data = json.loads(semgrep_json.read_text(encoding="utf-8", errors="replace"))
    findings: List[Tuple[str, int, int]] = []
    for result in data.get("results", []) or []:
        rel_path = norm_rel_path(result.get("path") or "")
        start = result.get("start", {}) or {}
        end = result.get("end", {}) or {}
        start_line = int(start.get("line", 0) or 0)
        end_line = int(end.get("line", 0) or start_line)
        if rel_path and start_line > 0 and end_line > 0:
            findings.append((rel_path, start_line, end_line))
    return findings


def load_csv_rows(csv_path: Path) -> List[dict]:
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def repo_name_from_row(row: dict) -> str:
    full_name = (row.get("full_name") or "").strip().strip("/")
    return full_name.rsplit("/", 1)[-1] if "/" in full_name else full_name


def ensure_repo_cloned(projects_dir: Path, row: dict, git_depth: int) -> Tuple[Optional[Path], Optional[str]]:
    repo_name = repo_name_from_row(row)
    clone_url = (row.get("clone_url") or "").strip()
    if not repo_name:
        return None, "missing repo name in CSV"
    if not clone_url:
        return None, "missing clone_url in CSV"

    project_dir = (projects_dir / repo_name).resolve()
    if project_dir.exists():
        return (project_dir, None) if project_dir.is_dir() else (None, f"target path exists but is not a directory: {project_dir}")

    project_dir.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone"]
    if git_depth > 0:
        cmd.extend(["--depth", str(git_depth)])
    cmd.extend(["--recurse-submodules", "--shallow-submodules", clone_url, str(project_dir)])
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        return None, f"git clone failed (rc={proc.returncode}): {msg[:1000]}"
    return project_dir, None


def scan_codeql_repo(project_dir: Path, cwe3: str, codeql_cwe_root: Path, codeql_timeout: int) -> Tuple[Optional[List[Tuple[str, int, int]]], Optional[str]]:
    if cwe3 not in CODEQL_SUPPORTED_CWES:
        return [], f"CodeQL does not support CWE-{cwe3}"
    if not check_command(CODEQL_BIN):
        return None, "CodeQL not available on PATH"

    queries = resolve_cwe_queries_from_dir(codeql_cwe_root)
    target_num = int(cwe3)
    active_queries = []
    for query in queries:
        for part in Path(query).parts:
            match = re.match(r"(?i)^cwe-(\d+)$", part)
            if match and int(match.group(1)) == target_num:
                active_queries.append(query)
                break
    if not active_queries:
        return None, f"No CodeQL queries found for CWE-{cwe3} under {codeql_cwe_root}"

    with tempfile.TemporaryDirectory(prefix="codeql_db_") as dbdir:
        db_path = Path(dbdir) / "db"
        create_cmd = [
            CODEQL_BIN, "database", "create", str(db_path),
            f"--language={CODEQL_LANG}",
            "--source-root", str(project_dir),
            "--build-mode=none",
            "--threads=0",
            "--overwrite",
        ]
        rc, _, out, err = run_cmd(create_cmd, cwd=project_dir, timeout_sec=codeql_timeout)
        msg = (err or out or "").strip()
        if rc != 0:
            if rc == 124:
                return None, f"codeql database create timeout after {codeql_timeout}s"
            return None, f"codeql database create failed (rc={rc}): {msg[:2000]}"

        sarif_path = Path(dbdir) / "report.sarif"
        analyze_cmd = [
            CODEQL_BIN, "database", "analyze", str(db_path),
            *active_queries,
            "--format=sarif-latest",
            "--output", str(sarif_path),
        ]
        rc, _, out, err = run_cmd(analyze_cmd, cwd=project_dir, timeout_sec=codeql_timeout)
        msg = (err or out or "").strip()
        if rc != 0:
            if rc == 124:
                return None, f"codeql analyze timeout after {codeql_timeout}s"
            return None, f"codeql analyze failed (rc={rc}): {msg[:2000]}"
        return parse_sarif_results(sarif_path, cwe3), None


def scan_semgrep_repo(project_dir: Path, cwe3: str) -> Tuple[List[Tuple[str, int, int]], Optional[str]]:
    if cwe3 not in SEMGREP_RULES:
        return [], f"Semgrep does not support CWE-{cwe3}"
    if not check_command("semgrep"):
        return [], "Semgrep not available on PATH"

    configs = SEMGREP_RULES.get(cwe3, [])
    merged = {"results": [], "errors": [], "meta": {"cwe": cwe3, "configs": configs, "target": "."}}
    any_parse_ok = False

    with tempfile.TemporaryDirectory(prefix="semgrep_scan_") as tmpdir:
        tmp_root = Path(tmpdir)
        for index, config in enumerate(configs, 1):
            per_path = tmp_root / f"semgrep_{index:02d}.json"
            cmd = [
                "semgrep", "scan",
                "--config", config,
                "--json",
                "--output", str(per_path),
                "--metrics=off",
                "--quiet",
                ".",
            ]
            rc, _, out, err = run_cmd(cmd, cwd=project_dir)
            if not per_path.exists():
                merged["errors"].append({"config": config, "error": f"no output file (rc={rc}): {(err or out or '').strip()[:1000]}"})
                continue
            try:
                data = json.loads(per_path.read_text(encoding="utf-8", errors="replace"))
                merged["results"].extend(data.get("results", []) or [])
                merged["errors"].extend(data.get("errors", []) or [])
                any_parse_ok = True
            except Exception as exc:
                merged["errors"].append({"config": config, "error": f"json parse failed: {exc}"})

        merged_path = tmp_root / "semgrep.json"
        merged_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
        findings = parse_semgrep_results(merged_path)
        if any_parse_ok:
            return findings, None
        return findings, f"Semgrep outputs not parseable for CWE-{cwe3}"


def collect_file_ranges(findings: Sequence[Tuple[str, int, int]]) -> Dict[str, List[Tuple[int, int]]]:
    file_ranges: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
    for rel_path, start_line, end_line in findings:
        if rel_path and start_line > 0 and end_line > 0:
            file_ranges[rel_path].append((start_line, end_line))
    return dict(file_ranges)


def apply_removals(project_copy: Path, file_ranges: Dict[str, List[Tuple[int, int]]]) -> Dict[str, List[List[int]]]:
    report: Dict[str, List[List[int]]] = {}
    for rel_path, ranges in sorted(file_ranges.items()):
        merged = merge_ranges(ranges)
        target_path = (project_copy / rel_path).resolve()
        if not target_path.exists():
            continue
        with target_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            lines = handle.readlines()
        for start_line, end_line in sorted(merged, reverse=True):
            blank_full_lines(lines, start_line, end_line)
        with target_path.open("w", encoding="utf-8", newline="") as handle:
            handle.writelines(lines)
        report[rel_path] = [[start_line, end_line] for start_line, end_line in merged]
    return report


def write_project_outputs(project_copy: Path, report: Dict[str, List[List[int]]]) -> List[str]:
    (project_copy / "removed_ranges.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    prompt_lines = sorted(report.keys())
    with (project_copy / "prompt.txt").open("w", encoding="utf-8") as handle:
        for rel_path in prompt_lines:
            handle.write(rel_path + "\n")
    return prompt_lines


def append_global_prompt(global_prompt_path: Path, project_name: str, prompt_lines: Sequence[str], max_lines: int) -> int:
    existing_count = count_lines(global_prompt_path)
    if max_lines > 0 and existing_count >= max_lines:
        return existing_count
    remaining = max_lines - existing_count if max_lines > 0 else None
    lines_to_write = list(prompt_lines if remaining is None else prompt_lines[:remaining])
    if not lines_to_write:
        return existing_count
    global_prompt_path.parent.mkdir(parents=True, exist_ok=True)
    with global_prompt_path.open("a", encoding="utf-8") as handle:
        for rel_path in lines_to_write:
            handle.write(f"{project_name}\t{rel_path}\n")
    return existing_count + len(lines_to_write)


def build_output_project_dir(output_dir: Path, project_name: str, cwe3: str) -> Path:
    return output_dir / f"{safe_name(project_name)}__CWE-{cwe3}__CODEQL_SEMGREP_LINES"


def scan_project(project_dir: Path, cwe3: str, codeql_cwe_root: Path, codeql_timeout: int) -> Tuple[Optional[Dict[str, List[Tuple[int, int]]]], List[str]]:
    codeql_findings, codeql_failure = scan_codeql_repo(project_dir, cwe3, codeql_cwe_root, codeql_timeout)
    if codeql_failure and codeql_findings is None:
        return None, [codeql_failure]
    semgrep_findings, semgrep_failure = scan_semgrep_repo(project_dir, cwe3)
    messages: List[str] = []
    if codeql_failure:
        messages.append(codeql_failure)
    if semgrep_failure:
        messages.append(semgrep_failure)
    merged_ranges = collect_file_ranges([*(codeql_findings or []), *semgrep_findings])
    return merged_ranges, messages


def process_project(row: dict, project_dir: Path, output_dir: Path, cwe3: str, codeql_cwe_root: Path, codeql_timeout: int) -> Tuple[str, List[str], int]:
    full_name = (row.get("full_name") or "").strip() or project_dir.name
    file_ranges, messages = scan_project(project_dir, cwe3, codeql_cwe_root, codeql_timeout)
    if file_ranges is None:
        print(f"[SKIP] {full_name}: {messages[0]}")
        return "skipped", messages, 0
    if not file_ranges:
        extra = f" ({'; '.join(messages)})" if messages else ""
        print(f"[CLEAN] {full_name}: no CWE-{cwe3} findings{extra}")
        return "clean", messages, 0

    project_copy = build_output_project_dir(output_dir, project_dir.name, cwe3)
    if project_copy.exists():
        shutil.rmtree(project_copy)
    shutil.copytree(project_dir, project_copy, dirs_exist_ok=True)
    report = apply_removals(project_copy, file_ranges)
    prompt_lines = write_project_outputs(project_copy, report)
    extra = f" warnings={'; '.join(messages)}" if messages else ""
    print(f"[REMOVED] {full_name}: files={len(prompt_lines)} output={project_copy}{extra}")
    return "removed", messages, len(prompt_lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Clone Java repos from repos_java.csv, scan a single CWE with CodeQL + Semgrep, and remove vulnerable lines.")
    parser.add_argument("--csv", default="./repos/repos_java.csv", help="Path to repos_java.csv")
    parser.add_argument("--projects-dir", default="./projects", help="Directory where repos are cloned")
    parser.add_argument("--output-dir", default="./rm_output", help="Output root for copied and modified projects")
    parser.add_argument("--global-prompt", default=None, help="Global prompt.txt path (default: <output-dir>/prompt.txt)")
    parser.add_argument("--cwe", required=True, help="Target CWE, for example 022 or CWE-022")
    parser.add_argument("--codeql-cwe-root", default=None, help="Override CodeQL Java query root")
    parser.add_argument("--codeql-timeout", type=int, default=360, help="Timeout in seconds for codeql database create/analyze")
    parser.add_argument("--global-prompt-max-lines", type=int, default=100, help="Stop when global prompt.txt reaches this line count; 0 means unlimited")
    parser.add_argument("--limit-projects", type=int, default=0, help="Maximum number of CSV rows to inspect; 0 means unlimited")
    parser.add_argument("--project-filter", default=None, help="Only process rows whose full_name contains this string")
    parser.add_argument("--git-depth", type=int, default=1, help="git clone depth; 0 means full clone")
    args = parser.parse_args()

    cwe3 = normalize_cwe(args.cwe)
    if cwe3 not in SUPPORTED_CWES:
        print(f"[ERROR] CWE-{cwe3} is not supported")
        return 2

    csv_path = Path(args.csv).expanduser().resolve()
    projects_dir = Path(args.projects_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    global_prompt_path = Path(args.global_prompt).expanduser().resolve() if args.global_prompt else (output_dir / "prompt.txt")
    if not csv_path.exists():
        print(f"[ERROR] csv not found: {csv_path}")
        return 2

    codeql_cwe_root = resolve_codeql_cwe_root(args.codeql_cwe_root)
    if cwe3 in CODEQL_SUPPORTED_CWES and not codeql_cwe_root:
        print("[ERROR] CodeQL Java CWE query root not found. Use --codeql-cwe-root or edit DEFAULT_CODEQL_CWE_ROOT.")
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)
    projects_dir.mkdir(parents=True, exist_ok=True)

    initial_global_lines = count_lines(global_prompt_path)
    if args.global_prompt_max_lines > 0 and initial_global_lines >= args.global_prompt_max_lines:
        print(f"[STOP] global prompt already reached limit: {initial_global_lines}/{args.global_prompt_max_lines}")
        return 0

    rows = load_csv_rows(csv_path)
    inspected = 0
    cloned = 0
    removed_projects = 0
    clean_projects = 0
    skipped_projects = 0
    clone_failed = 0
    global_lines = initial_global_lines

    for row in rows:
        full_name = (row.get("full_name") or "").strip()
        if not full_name:
            continue
        if args.project_filter and args.project_filter not in full_name:
            continue
        if args.limit_projects > 0 and inspected >= args.limit_projects:
            break
        if args.global_prompt_max_lines > 0 and global_lines >= args.global_prompt_max_lines:
            print(f"[STOP] global prompt reached limit: {global_lines}/{args.global_prompt_max_lines}")
            break

        inspected += 1
        repo_name = repo_name_from_row(row)
        expected_dir = projects_dir / repo_name
        already_exists = expected_dir.exists()
        project_dir, clone_error = ensure_repo_cloned(projects_dir, row, args.git_depth)
        if clone_error:
            print(f"[SKIP] {full_name}: {clone_error}")
            clone_failed += 1
            continue
        if not already_exists:
            cloned += 1
            print(f"[CLONED] {full_name} -> {project_dir}")

        status, _, prompt_line_count = process_project(
            row=row,
            project_dir=project_dir,
            output_dir=output_dir,
            cwe3=cwe3,
            codeql_cwe_root=codeql_cwe_root or DEFAULT_CODEQL_CWE_ROOT,
            codeql_timeout=args.codeql_timeout,
        )
        if status == "removed":
            removed_projects += 1
            project_prompt_lines = (build_output_project_dir(output_dir, project_dir.name, cwe3) / "prompt.txt").read_text(encoding="utf-8").splitlines()
            global_lines = append_global_prompt(
                global_prompt_path=global_prompt_path,
                project_name=repo_name,
                prompt_lines=project_prompt_lines,
                max_lines=args.global_prompt_max_lines,
            )
            print(f"[PROMPT] {full_name}: project_lines={prompt_line_count} global_lines={global_lines}")
        elif status == "clean":
            clean_projects += 1
        else:
            skipped_projects += 1

    print(
        f"[SUMMARY] inspected={inspected} cloned={cloned} removed={removed_projects} clean={clean_projects} "
        f"skipped={skipped_projects} clone_failed={clone_failed} global_prompt_lines={global_lines}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
