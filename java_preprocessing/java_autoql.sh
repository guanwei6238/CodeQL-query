#!/bin/bash
# example: ./java_autoql.sh owner__repo ../projects/owner__repo/
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $(basename "$0") <db name> <project root>"
  exit 1
fi

DB_NAME="$1"
SRC_ROOT="$2"

codeql_db_dir="/home/sixsquare/codeQL/db"
output_dir="/home/sixsquare/codeQL/java_preprocessing/java_query_output/$DB_NAME"
ql_dir="/home/sixsquare/codeQL/java-ql"
gen_json_py="/home/sixsquare/codeQL/gen_cwe_json.py"

echo "建立輸出資料夾: $output_dir"
mkdir -p "$output_dir"

ql_list=("CWE-022" "CWE-078" "CWE-079" "CWE-095" "CWE-113" "CWE-117" "CWE-326" "CWE-327" "CWE-329" "CWE-347" "CWE-377" "CWE-502" "CWE-643" "CWE-760" "CWE-918" "CWE-943" "CWE-1333")

db_path="$codeql_db_dir/$DB_NAME"
rm -rf "$db_path" || true

echo "[+] Creating CodeQL DB with --build-mode=none"
codeql database create "$db_path" \
  --language=java \
  --source-root "$SRC_ROOT" \
  --build-mode=none \
  --threads=0 \
  --overwrite

if ! ls -d "$db_path"/db-* >/dev/null 2>&1; then
  echo "[!] codeql 無法成功建立 Java DB: $DB_NAME"
  echo "[!] DB path: $db_path"
  exit 1
fi

for cwe_number in "${ql_list[@]}"; do
  ql_file="${ql_dir}/${cwe_number}.ql"
  if [[ ! -f "$ql_file" ]]; then
    echo "[!] Missing query: $ql_file"
    exit 1
  fi

  codeql query run "$ql_file" \
    --database "$db_path" \
    --output "${output_dir}/${cwe_number}.bqrs"

  codeql bqrs decode \
    --format=csv \
    --output "${output_dir}/${cwe_number}.csv" \
    "${output_dir}/${cwe_number}.bqrs"
done

python3 "$gen_json_py" "$output_dir" "$DB_NAME"

rm -f "${output_dir}"/*.bqrs
rm -rf "$db_path"
exit 0
