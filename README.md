# CodeQL-query
本專案協助你以 CodeQL 產出「移除程式碼的依據 JSON」，並把指定專案複製到輸出目錄後，依 JSON 位置將目標區段以空字串取代（保留換行、不改行數），最後輸出刪除報告。
## 環境
os:ubuntu24.04
Python 3.10.12
bandit 1.8.6(確保版本在這之上)
codeql 2.22.4.
## 初始化資料夾
```bash
mkdir projects # 其他專案的暫存資料夾
mkdir db # codeQL編譯後的DB存放位子
mkdir testing_db # 最後靜態分析codeql db放的位子
mkdir result # 最後靜態分析後的結果
```
## python_autoql.sh
將專案使用 CodeQL 建 DB，並執行查詢。
```bash
sudo chmod +x ./python_autoql.sh
./python_autoql.sh <project name> <project_dir>
# ./python_autoql.sh yt-dlp ./projects/yt-dlp/
```
## batch_autoql_from_csv.sh
讀取 CSV 批次前處理並跑查詢。
```bash
# batch_autoql_from_csv.sh -c repos_python.csv -p ./projects [-a ./python_autoql.sh] [-l Python|"" for all] [-d 1] [-m N] [-S seconds]
batch_autoql_from_csv.sh -c repos_python.csv -p ./projects -a ./python_autoql.sh -l Python -d 1 -S 2
```

## rm_project_call_function.py
將專案根據前處理後的json進行移除程式碼的動作，並且會將專案刪除code的專案放到rm_output目錄底下。
每個專案都會有prompt.txt(只有mode=call時才會出現)、removed_ranges.json
使用方式
```
python3 rm_project_call_function.py <project_root> \
  --json <path/to/index.json> \
  [--mode call|caller|bb] \
  [--above N --below M] \
  [--cwe 022 095 ...] \
  [--callee os.path.join http.server.BaseHTTPRequestHandler.send_header ...] \
  [-o <output_dir>]
```
Example:
```bash
# 可以使用 python3 rm_project_call_function.py -h取得更多細節
python3 rm_project_call_function.py ./projects/yt-dlp/ --json ./python_query_output/yt-dlp/yt-dlp.json --cwe 022 095 --callee open os.path.join ## 常用方式
```

### 模式與行為
- call（預設）：
  - 未指定 --above/--below：只刪 callSL ~ callEL 區段（不動換行）。
  - 指定 --above/--below：將 callSL..callEL「整行清空」到 (callSL-above) .. (callEL+below)，且範圍限制在該函式內（夾在 funcStart..funcEnd），保留原 EOL，不改行數。
- caller：整個函式 funcStart..funcEnd 清空（整行清空）。
- bb：只刪 (bbSL,bbSC) ~ (bbEL,bbEC) 區段（不動換行）。

### 輸出與命名
- 複製目的地：
  rm_output/<project>__CWE-<...>__CAL-<...>-<hash>__M-<mode>/
- 刪除報告 removed_ranges.json（路徑為相對於複製後專案根）：

同檔案多段會合併重疊或相鄰範圍；行數永遠不會位移（整行清空保留 EOL；行內刪除不觸及換行）。

### 注意事項
- --cwe / --callee 若不指定，代表全部搜尋。
- --callee 使用完全比對鍵名。

## is_cwe_testing.sh
使用靜態分析器去測試指定的CWE弱點。
安裝Bandit & semgrep
```bash
python3.12 -m venv .venv
source ./.venv/bin/activate
pip install bandit semgrep
```
安裝CodeQL
[參考](https://medium.com/ricos-note/codeql%E5%9C%A8ubuntu%E5%BB%BA%E7%BD%AE%E5%92%8C%E5%88%86%E6%9E%90-net-90b7a7eb008f)
```bash
wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.22.4/codeql-bundle-linux64.tar.gz

tar -xvzf codeql-bundle-linux64.tar.gz

vim /etc/profile
export PATH=$PATH:/home/rico/codeqlsrc/codeql
source /etc/profile
```

下載內建查詢library
```bash
codeql pack download codeql/python-queries
# 要看一下是否存在 ~/.codeql/packages/codeql/python-queries/x.x.x/Security/ 這個資料夾
```
example
```bash
chmod +x run_cwe_queries.sh
source .venv/bin/activate #如果是使用pip 安裝bandit才要使用venv
./is_cwe_testing.sh --project ./projects/yt-dlp/ --cwe 022,078 --security-dir ~/.codeql/packages/codeql/python-queries/1.6.5/Security --db-dir ./testing_db/ --out ./result/ --overwrite
# 使用help可以查看詳細內容
# 全部掃描./is_cwe_testing.sh --project ./projects/yt-dlp/ --cwe 022,078,079,095,113,117,326,327,347,377,502,643,918,943,1333 --security-dir ~/.codeql/packages/codeql/python-queries/1.6.5/Security --db-dir ./testing_db/ --out ./result/ --overwrite
# ./is_cwe_testing.sh --help
```
codeql掃描的部分建議參考[官方查詢](https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/python-built-in-queries)因為一個腳本可能對應多個CWE，所以可能參數要下其他編號才能掃描到目標CWE(ex. 要掃 CWE1333 參數要輸入 730)

## remote_analyse.ps1
用來把 Windows 本機的專案丟到遠端 Ubuntu（VM/實體機），在遠端執行 is_cwe_testing.sh 做分析，最後把結果抓回本機。
先決條件
- 依 `is_cwe_testing.sh` 的說明在遠端安裝好相依套件。
- 遠端需能透過 SSH 連線（要已設定免密碼登入）。
- Windows 需有 OpenSSH（ssh/scp）可用。

### 啟動步驟
1. 找到遠端 `codeql` 可執行檔所在目錄（取第一層目錄，不是二段）：
    ```bash
    which codeql
    # example: /home/sixsquare/codeql/codeql  ->  取用 /home/sixsquare/codeql
    ```
2. 在 script `param(...)` 的 `RemotePathPrepend` 第一個元素換成你的路徑（或直接用參數帶入，見下文）：
    ```ps1
    [string[]]$RemotePathPrepend = @('<請取代這邊>', '$HOME/.local/bin')
    ```
3. 設定固定參數
以下參數可以直接固定才不需要每次執行 script 輸入很多參數
    | 參數| 說明 |
    |---|---|
    |RemoteHost |遠端主機 IP |
    |Port |SSH 連線埠 |
    |RemoteUser |遠端使用者 |
    |RemoteDir |遠端工作根目錄（腳本、DB、結果都在這底下） |
    |OutWin |將分析結果輸出到這個資料夾 |
    |SecurityDir|CodeQL Python Security queries 路徑|
    |RemotePathPrepend|codeql 的執行路徑|
4. 執行
    ```
    .\remote_analyse.ps1 -ProjWin .\yt-dlp\  -Cwes 022,078
    ```

## check_cwe_csvs.py
檢查前處理有哪些專案是好的或壞的
```bash
# 找成功前處理的
python3 ./check_cwe_csvs.py --input-csv ./repos/cmake_candidates_2nd.csv --base-dir ./cpp_query_output/ --output-csv complete.csv --mode complete
# 找失敗前處理的
python3 check_cwe_csvs.py --input-csv repos_python.csv --base-dir ./python_query_output --output-csv missing.csv
```
## cpp_preprocessing/cpp_cwe_scan.sh
靜態分析器安裝
```bash
sudo apt install flawfinder cppcheck
```
使用範例
```bash
cd cpp_preprocessing
bash cpp_cwe_scan.sh --project ../projects/casadi/ --cwe "022, 078, 327" --out ./results_c_cpp --threads 8
```

## java install
```bash
sudo apt update
sudo apt install -y openjdk-8-jdk openjdk-11-jdk openjdk-17-jdk openjdk-21-jdk ant
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
echo 'source "$HOME/.sdkman/bin/sdkman-init.sh"' >> ~/.bashrc
sdk version
sdk install maven 3.9.9
sdk install gradle 8.10.2
sdk default maven 3.9.9
sdk default gradle 8.10.2
```

## data_process
將自動化後的 query_statistics 資料夾轉成報告
### 安裝
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install rust-script # 要下載這個才能執行單一rs檔案
```
### 使用
```bash
rust-script data_process.rs
# 查看參數
rust-script data_process.rs -h
```