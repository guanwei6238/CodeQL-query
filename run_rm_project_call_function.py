#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# python3 run_rm_project_call_function.py --project cpp-jwt --cwe 078
# python3 run_rm_project_call_function.py --all --cwe 078
# python3 run_rm_project_call_function.py --all --cwe 078 --one-fn-per-file

import argparse
import subprocess
from pathlib import Path
from typing import List, Tuple


DEFAULT_PROJECTS_DIR = Path("./projects")
DEFAULT_JSON_ROOT = Path("./java_preprocessing/java_query_output")
DEFAULT_TARGET_SCRIPT = Path("./rm_project_call_function.py")


def normalize_cwe(cwe: str) -> str:
    """
    Accept '78' or '078' -> '078'
    Keep digits only; if non-digit, raise.
    """
    cwe = cwe.strip()
    if not cwe.isdigit():
        raise ValueError(f"--cwe must be digits only (got: {cwe!r})")
    return cwe.zfill(3)


def list_projects(projects_dir: Path) -> List[str]:
    if not projects_dir.exists():
        return []
    return sorted([p.name for p in projects_dir.iterdir() if p.is_dir()])


def build_paths(project_name: str, projects_dir: Path, json_root: Path) -> Tuple[Path, Path]:
    project_dir = projects_dir / project_name
    json_path = json_root / project_name / f"{project_name}.json"
    return project_dir, json_path


def run_one(
    target_script: Path,
    project_dir: Path,
    json_path: Path,
    cwe: str,
    dry_run: bool,
    one_fn_per_file: bool,
) -> int:
    cmd = [
        "python3",
        str(target_script),
        str(project_dir),
        "--json",
        str(json_path),
        "--cwe",
        cwe,
    ]

    # NEW: pass-through flag
    if one_fn_per_file:
        cmd.append("--one-fn-per-file")

    if dry_run:
        print("[DRY-RUN]", " ".join(cmd))
        return 0

    print("[RUN]", " ".join(cmd))
    proc = subprocess.run(cmd)
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run rm_project_call_function.py for one project or all projects with per-project JSON existence check."
    )
    parser.add_argument(
        "--target-script",
        default=str(DEFAULT_TARGET_SCRIPT),
        help="Path to rm_project_call_function.py (default: ./rm_project_call_function.py)",
    )
    parser.add_argument(
        "--projects-dir",
        default=str(DEFAULT_PROJECTS_DIR),
        help="Projects root directory (default: ./projects)",
    )
    parser.add_argument(
        "--json-root",
        default=str(DEFAULT_JSON_ROOT),
        help="JSON root directory (default: ./cpp_preprocessing/cpp_query_output)",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--project",
        help="Project name under ./projects/<project>/ (e.g., cpp-jwt)",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Run for all projects under ./projects/",
    )

    parser.add_argument(
        "--cwe",
        required=True,
        help="CWE id (e.g., 078 or 78)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing",
    )
    parser.add_argument(
        "--continue-on-fail",
        action="store_true",
        help="Continue other projects even if one fails (for --all). Default: stop on first failure.",
    )

    # NEW: expose rm_project_call_function.py behavior toggle
    parser.add_argument(
        "--one-fn-per-file",
        action="store_true",
        help="In each file, only remove within a single enclosing function (pass-through to target script).",
    )

    args = parser.parse_args()

    target_script = Path(args.target_script)
    projects_dir = Path(args.projects_dir)
    json_root = Path(args.json_root)

    try:
        cwe = normalize_cwe(args.cwe)
    except ValueError as e:
        print(f"[ERROR] {e}")
        return 2

    if not target_script.exists():
        print(f"[ERROR] target script not found: {target_script}")
        return 2

    if args.project:
        project_names = [args.project]
    else:
        project_names = list_projects(projects_dir)
        if not project_names:
            print(f"[ERROR] no projects found under: {projects_dir}")
            return 2

    skipped = []
    for name in project_names:
        project_dir, json_path = build_paths(name, projects_dir, json_root)

        if not project_dir.exists():
            skipped.append((name, f"project dir missing: {project_dir}"))
            continue

        if not json_path.exists():
            skipped.append((name, f"json missing: {json_path}"))
            continue

        rc = run_one(
            target_script=target_script,
            project_dir=project_dir,
            json_path=json_path,
            cwe=cwe,
            dry_run=args.dry_run,
            one_fn_per_file=args.one_fn_per_file,
        )
        if rc != 0:
            print(f"[FAIL] project={name} rc={rc}")
            if not args.continue_on_fail:
                if skipped:
                    print("\n[SKIPPED]")
                    for n, reason in skipped:
                        print(f"  - {n}: {reason}")
                return rc
        else:
            print(f"[OK] project={name}")

    if skipped:
        print("\n[SKIPPED]")
        for n, reason in skipped:
            print(f"  - {n}: {reason}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
