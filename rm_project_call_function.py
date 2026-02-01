import argparse
from pathlib import Path
import shutil
import re
import hashlib
import json
from typing import List, Tuple, Dict, Optional
from collections import defaultdict

# example:
# python3 rm_project_call_function.py ./projects/yt-dlp/ --json ./python_query_output/yt-dlp/yt-dlp.json --cwe 022 095 --one-fn-per-file

def normalize_cwes(cwes):
    if not cwes:
        return []
    out = set()
    for s in cwes:
        digits = re.sub(r"(?i)cwe[-_\s]*|[^0-9]", "", s).lstrip("0") or "0"
        if len(digits) <= 3:
            digits = digits.zfill(3)
        out.add(digits)
    return sorted(out)

def normalize_callees(callees):
    if not callees:
        return []
    clean = []
    seen = set()
    for c in callees:
        c = c.strip()
        if not c:
            continue
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$", c):
            continue
        if c not in seen:
            seen.add(c)
            clean.append(c)
    return sorted(clean)

def fs_safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)

FN, FS, FE, CSL, CSC, CEL, CEC, BBSL, BBSC, BBEL, BBEC = range(11)

def _norm_cwe_key_for_filter(s: str) -> str:
    digits = re.sub(r"(?i)cwe[-_\s]*|[^0-9]", "", s).lstrip("0") or "0"
    if len(digits) <= 3:
        digits = digits.zfill(3)
    return f"CWE-{digits}"

def _cwe_pass(cwe_key: str, filters):
    if not filters:
        return True
    norm_filters = {_norm_cwe_key_for_filter(x) for x in filters}
    return cwe_key in norm_filters

def _callee_pass(callee: str, filters):
    if not filters:
        return True
    return callee in set(filters)

def _strip_first_component(json_path: str) -> Path:
    parts = Path(json_path).parts
    rel = parts[1:] if len(parts) > 1 else parts
    return Path(*rel)

def _as_blocks(v):
    def _is_one(blk):
        if not isinstance(blk, list) or len(blk) != 11:
            return False
        fn_ok = (blk[FN] is None) or isinstance(blk[FN], str)
        ints_ok = all(isinstance(x, int) for x in blk[FS:])  # 後 10 欄
        return fn_ok and ints_ok

    if isinstance(v, list) and v and _is_one(v):
        return [v]
    if isinstance(v, list) and v and all(_is_one(x) for x in v):
        return v
    return []

def _iter_entries(data):
    if not isinstance(data, dict):
        raise ValueError("JSON 頂層必須是物件(dict)")
    for cwe_key, callee_map in data.items():
        if not isinstance(callee_map, dict):
            raise ValueError(f"{cwe_key} 的值必須是物件(callee 映射)")
        for callee, file_map in callee_map.items():
            if not isinstance(file_map, dict):
                raise ValueError(f"{cwe_key}/{callee} 必須是物件(file 映射)")
            for file_path, blocks_v in file_map.items():
                for blk in _as_blocks(blocks_v):
                    yield (cwe_key, callee, file_path, blk)

def preview_targets(cp_root: Path, json_file: Path, mode: str, above: int, below: int,
                    cwe_filters, callee_filters):
    cp_root = cp_root.expanduser().resolve()
    json_file = json_file.expanduser().resolve()

    with json_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    count = 0
    for cwe_key, callee, json_path, blk in _iter_entries(data):
        if not _cwe_pass(cwe_key, cwe_filters):
            continue
        if not _callee_pass(callee, callee_filters):
            continue

        rel_path = _strip_first_component(json_path)
        abs_path = (cp_root / rel_path).resolve()

        fn, fs, fe, csl, csc, cel, cec, bbsl, bbsc, bbel, bbec = blk

        if mode == "call":
            sel_start_line = max(1, csl - max(0, above))
            sel_end_line   = cel + max(0, below)
            sel = f"L{sel_start_line}:*  ~  L{sel_end_line}:*  (±{above}/{below})"
        elif mode == "caller":
            sel = f"L{fs}:1  ~  L{fe}:*"
        elif mode == "bb":
            sel = f"L{bbsl}:{bbsc}  ~  L{bbel}:{bbec}"
        else:
            sel = "(unknown mode)"

        print(f"[{cwe_key}] callee={callee}")
        print(f"  file : {abs_path}")
        print(f"  func : {fn!r}  L{fs} ~ L{fe}")
        print(f"  call : L{csl}:{csc}  ~  L{cel}:{cec}")
        print(f"  bb   : L{bbsl}:{bbsc}  ~  L{bbel}:{bbec}")
        print(f"  ==> SELECT [{mode}] : {sel}")
        print("-" * 80)
        count += 1

    if count == 0:
        print("(no targets matched)")

def _iter_entries_strict(data):
    if not isinstance(data, dict):
        raise ValueError("JSON 頂層必須是物件(dict)")
    for cwe_key, callee_map in data.items():
        if not isinstance(callee_map, dict):
            raise ValueError(f"{cwe_key} 的值必須是物件(callee 映射)")
        for callee, file_map in callee_map.items():
            if not isinstance(file_map, dict):
                raise ValueError(f"{cwe_key}/{callee} 必須是物件(file 映射)")
            for file_path, blocks_v in file_map.items():
                for blk in _as_blocks(blocks_v):
                    yield (cwe_key, callee, file_path, blk)

def _split_eol(line: str) -> Tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    if line.endswith("\r"):
        return line[:-1], "\r"
    return line, ""

def _blank_region_in_lines(lines: List[str], sL: int, sC: int, eL: int, eC: int, full_lines: bool):
    n = len(lines)
    sL = max(1, min(sL, n))
    eL = max(1, min(eL, n))
    if (eL, eC) < (sL, sC):
        sL, sC, eL, eC = eL, eC, sL, sC

    if full_lines:
        for L in range(sL, eL + 1):
            _, eol = _split_eol(lines[L - 1])
            lines[L - 1] = eol
        return

    if sL == eL:
        content, eol = _split_eol(lines[sL - 1])
        start = max(0, sC - 1)
        end = max(start, min(len(content), eC))
        new_content = content[:start] + content[end:]
        lines[sL - 1] = new_content + eol
        return

    content, eol = _split_eol(lines[sL - 1])
    start = max(0, sC - 1)
    start = min(start, len(content))
    lines[sL - 1] = content[:start] + eol

    for L in range(sL + 1, eL):
        _, eol_m = _split_eol(lines[L - 1])
        lines[L - 1] = eol_m

    contentE, eolE = _split_eol(lines[eL - 1])
    end = max(0, min(len(contentE), eC))
    lines[eL - 1] = contentE[end:] + eolE

def _merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not ranges:
        return []
    ranges.sort()
    merged = [list(ranges[0])]
    for a, b in ranges[1:]:
        last = merged[-1]
        if a <= last[1] + 1:
            last[1] = max(last[1], b)
        else:
            merged.append([a, b])
    return [tuple(x) for x in merged]

def _dedupe_and_coalesce_regions(regions):
    """
    regions: List[Tuple[sL,sC,eL,eC,full_lines]]
    回傳: 去重 + full-line 合併 + partial 被 full 覆蓋則剔除
    且依 (start line/col) 由大到小排序，便於原地刪除
    """
    uniq = []
    seen = set()
    for r in regions:
        key = (r[0], r[1], r[2], r[3], r[4])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)

    full_ranges = []
    partials = []
    for sL, sC, eL, eC, full in uniq:
        if full:
            full_ranges.append((sL, eL))
        else:
            partials.append((sL, sC, eL, eC))

    merged_full = _merge_ranges(full_ranges)

    def covered_by_full(sL, eL):
        for a, b in merged_full:
            if sL >= a and eL <= b:
                return True
        return False

    kept_partials = []
    seen_partials = set()
    for sL, sC, eL, eC in partials:
        if covered_by_full(sL, eL):
            continue
        k = (sL, sC, eL, eC)
        if k in seen_partials:
            continue
        seen_partials.add(k)
        kept_partials.append((sL, sC, eL, eC))

    out = []
    for a, b in merged_full:
        out.append((a, 1, b, 10**9, True))
    for sL, sC, eL, eC in kept_partials:
        out.append((sL, sC, eL, eC, False))
    out.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return out

def _merge_ranges_by_fn(ranges_with_fn):
    """
    ranges_with_fn: List[Tuple[int,int,str]]
    回傳: List[Tuple[int,int,str]]，同一個 functionName 的區段才會合併（相鄰或重疊）
    """
    buckets = defaultdict(list)
    for s, e, fn in ranges_with_fn:
        buckets[fn].append((s, e))

    out = []
    for fn, rs in buckets.items():
        rs.sort()
        merged = [list(rs[0])]
        for a, b in rs[1:]:
            last = merged[-1]
            if a <= last[1] + 1:
                last[1] = max(last[1], b)
            else:
                merged.append([a, b])
        out.extend([(a, b, fn) for a, b in merged])

    out.sort(key=lambda x: (x[0], x[1], x[2] or ""))
    return out

def _pick_single_fn_for_file(items: List[Tuple[int, Optional[str]]]) -> Optional[str]:
    """
    items: List of (order_index, fn)
    挑選命中數最多的 fn；同票時優先較早出現者；再以名稱字典序穩定 tie-break。
    另外：若同檔案存在非 None 的 fn，則不會選 None。
    """
    if not items:
        return None

    # 是否存在有效 fn（非 None、非空）
    has_named = any(fn for _, fn in items)

    count = defaultdict(int)
    first_idx = {}
    for idx, fn in items:
        if has_named and not fn:
            continue
        count[fn] += 1
        if fn not in first_idx:
            first_idx[fn] = idx

    if not count:
        return None

    def key(fn):
        # max count first; then smaller first_idx; then lexicographic name for stability
        return (count[fn], -first_idx.get(fn, 10**18), "" if fn is None else fn)

    # 先找 max count
    max_cnt = max(count.values())
    candidates = [fn for fn, c in count.items() if c == max_cnt]
    # tie-break: earliest appearance
    min_first = min(first_idx.get(fn, 10**18) for fn in candidates)
    candidates = [fn for fn in candidates if first_idx.get(fn, 10**18) == min_first]
    # final: lexicographic
    candidates.sort(key=lambda x: "" if x is None else x)
    return candidates[0]

def remove_targets_and_report(
    cp_root: Path,
    json_file: Path,
    mode: str,
    above: int,
    below: int,
    cwe_filters,
    callee_filters,
    one_fn_per_file: bool = False,
) -> Dict[str, List[Tuple[int, int, str]]]:
    cp_root = cp_root.expanduser().resolve()
    json_file = json_file.expanduser().resolve()

    with json_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # 先收集所有命中（便於做 one-fn-per-file 的篩選）
    collected = defaultdict(list)
    order = 0

    for cwe_key, callee, json_path, blk in _iter_entries_strict(data):
        if not _cwe_pass(cwe_key, cwe_filters):
            continue
        if not _callee_pass(callee, callee_filters):
            continue

        rel_path = _strip_first_component(json_path)
        abs_path = (cp_root / rel_path).resolve()

        fn, fs, fe, csl, csc, cel, cec, bbsl, bbsc, bbel, bbec = blk

        if mode == "call":
            if above > 0 or below > 0:
                sL = max(fs, csl - max(0, above))
                eL = min(fe, cel + max(0, below))
                if sL > eL:
                    continue
                region = (sL, 1, eL, 10**9, True)
                line_range = (sL, eL, fn)
            else:
                region = (csl, 1, cel, 10**9, True)
                line_range = (csl, cel, fn)
        elif mode == "caller":
            region = (fs, 1, fe, 10**9, True)
            line_range = (fs, fe, fn)
        elif mode == "bb":
            region = (bbsl, bbsc, bbel, bbec, False)
            line_range = (bbsl, bbel, fn)
        else:
            continue

        collected[abs_path].append((order, fn, region, line_range))
        order += 1

    # 若啟用：每個檔案只保留同一個 fn
    per_file_regions: Dict[Path, List[Tuple[int, int, int, int, bool]]] = {}
    per_file_line_ranges: Dict[Path, List[Tuple[int, int, str]]] = {}

    for fpath, items in collected.items():
        if one_fn_per_file:
            chosen_fn = _pick_single_fn_for_file([(idx, fn) for (idx, fn, _, _) in items])
            items = [x for x in items if x[1] == chosen_fn]
        for _, fn, region, line_range in items:
            per_file_regions.setdefault(fpath, []).append(region)
            per_file_line_ranges.setdefault(fpath, []).append(line_range)

    # 實際修改檔案
    for fpath, regions in per_file_regions.items():
        if not fpath.exists():
            continue
        regions = _dedupe_and_coalesce_regions(regions)

        with fpath.open("r", encoding="utf-8", errors="ignore", newline="") as fr:
            lines = fr.readlines()

        for sL, sC, eL, eC, full_lines in regions:
            _blank_region_in_lines(lines, sL, sC, eL, eC, full_lines)

        with fpath.open("w", encoding="utf-8", newline="") as fw:
            fw.writelines(lines)

    # report
    report: Dict[str, List[Tuple[int, int, str]]] = {}
    for fpath, ranges in per_file_line_ranges.items():
        rel = fpath.resolve().relative_to(cp_root.resolve()).as_posix()
        merged = _merge_ranges_by_fn(ranges)
        report[rel] = [[s, e, fn] for (s, e, fn) in merged]

    out_path = cp_root / "removed_ranges.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[report] {out_path}")

    if mode == "call":
        prompt_lines: List[str] = []
        for rel, ranges in sorted(report.items(), key=lambda kv: kv[0]):
            if not any(fn for (_, _, fn) in ranges):
                continue
            prompt_lines.append(rel)

        prompt_path = cp_root / "prompt.txt"
        with prompt_path.open("w", encoding="utf-8") as pf:
            for line in prompt_lines:
                pf.write(line + "\n")
        print(f"[prompt] {prompt_path}")

    return report

def main():
    ap = argparse.ArgumentParser(description="從給的專案移除指定的function call")
    ap.add_argument("project_root", help="專案的根目錄")
    ap.add_argument("-o", "--output", help="輸出到的資料夾")
    ap.add_argument("--json", required=True, help="專案的CWE json")
    ap.add_argument("--mode", choices=["call", "caller", "bb"], default="call", help="刪除模式")
    ap.add_argument("--above", type=int, default=0, help="call 模式：向上額外刪除的行數(預設 0)")
    ap.add_argument("--below", type=int, default=0, help="call 模式：向下額外刪除的行數(預設 0)")
    ap.add_argument("--cwe", nargs="+", help="僅處理指定 CWE(可多個；接受 '022' 或 'CWE-022')")
    ap.add_argument("--callee", nargs="+", help="僅處理指定 callee(可多個完全比對)")

    # NEW
    ap.add_argument(
        "--one-fn-per-file",
        action="store_true",
        help="同一個檔案只會在同一個函式(fn)內移除；會自動挑選該檔案命中次數最多的 fn",
    )

    args = ap.parse_args()

    p_root = Path(args.project_root).expanduser().resolve()
    json_file = Path(args.json).expanduser().resolve()
    if args.output:
        output_dir = Path(args.output).expanduser().resolve()
    else:
        output_dir = (Path.cwd() / "rm_output").resolve()

    cwes = normalize_cwes(args.cwe)
    callees = normalize_callees(args.callee)

    cwe_tag = f"CWE-{'+'.join(cwes)}" if cwes else "CWE-ALL"
    callee_joined = "+".join(callees) if callees else "ALL"
    callee_hash = hashlib.sha1(callee_joined.encode()).hexdigest()[:8]
    callee_prefix = fs_safe(callee_joined)[:32]
    callee_tag = f"CAL-{callee_prefix}-{callee_hash}"
    mode_tag = f"M-{args.mode}"
    extra_tag = "ONEFN" if args.one_fn_per_file else "MULTIFN"

    raw_cp_name = f"{p_root.name}__{cwe_tag}__{callee_tag}__{mode_tag}__{extra_tag}"
    if len(raw_cp_name) > 120:
        suffix = hashlib.sha1(raw_cp_name.encode()).hexdigest()[:10]
        raw_cp_name = raw_cp_name[:100] + "__" + suffix

    output_dir.mkdir(parents=True, exist_ok=True)
    cp_root = (output_dir / raw_cp_name)
    shutil.copytree(p_root, cp_root, dirs_exist_ok=True)

    remove_targets_and_report(
        cp_root=cp_root,
        json_file=json_file,
        mode=args.mode,
        above=args.above,
        below=args.below,
        cwe_filters=cwes,
        callee_filters=callees,
        one_fn_per_file=args.one_fn_per_file,
    )

if __name__ == '__main__':
    main()
