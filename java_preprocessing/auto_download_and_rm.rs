#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! clap = { version = "4", features = ["derive"] }
//! csv = "1.4.0"
//! serde = { version = "1.0.228", features = ["derive"] }
//! serde_json = "1.0.148"
//! ```
/// 使用實際的將 java_autoql.sh 的掃描部分 (最後for 迴圈) 註解掉。
use clap::Parser;
use csv::Reader;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    path::PathBuf,
    process::{Command, ExitStatus},
    time::Instant,
};
const LIMIT_SECS: u64 = 270; // 4.5 minutes
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// number of cwe for target
    #[arg(long)]
    cwe: String,

    /// csv path
    #[arg(long, default_value = "../repos/repos_java.csv")]
    csv: String,

    /// need file number
    #[arg(long, default_value_t = 100)]
    file_num: usize,
    /// clone output dir
    #[arg(long, default_value = "../projects/")]
    output_dir: String,
}

#[derive(Debug, Deserialize)]
struct Row {
    full_name: String,
    clone_url: String,
}
fn clone_repo(clone_url: &str, project_dir: &PathBuf) -> ExitStatus {
    let status: std::process::ExitStatus = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--recurse-submodules")
        .arg(clone_url)
        .arg(&project_dir)
        .status()
        .expect("failed to execute git clone");
    status
}
fn main() {
    let args = Args::parse();
    let cwe = format!("CWE-{}", args.cwe);
    let file = File::open(&args.csv).expect("Cannot open CSV file");
    let mut rdr = Reader::from_reader(file);
    let time_cache_path = "./java_time_cache.txt";
    let mut time_cache = HashMap::new();
    if let Ok(s) = fs::read_to_string(time_cache_path) {
        for line in s.lines() {
            let mut it = line.split_whitespace();
            if let (Some(name), Some(secs)) = (it.next(), it.next()) {
                if let Ok(secs) = secs.parse::<u64>() {
                    time_cache.insert(name.to_string(), secs);
                }
            }
        }
    }
    let mut count = 0;
    for res in rdr.deserialize::<Row>() {
        let row = res.expect("Cannot deserialize row");
        let repo_name = row
            .full_name
            .split('/')
            .last()
            .expect("repo name not found.");
        let json_path = format!("./java_query_output/{}/{}.json", &repo_name, &repo_name);
        let json_text = match fs::read_to_string(&json_path) {
            Ok(text) => text,
            Err(_) => continue,
        };

        let json_value: Value = match serde_json::from_str(&json_text) {
            Ok(val) => val,
            Err(_) => continue,
        };
        let mut file_paths = HashSet::new();
        let cwe_obj = json_value
            .get(&cwe)
            .expect("CWE not found")
            .as_object()
            .expect(&format!("{cwe} is not a JSON object"));
        for (_key, val) in cwe_obj {
            let files_obj = match val.as_object() {
                Some(o) => o,
                None => continue,
            };
            for file_path in files_obj.keys() {
                file_paths.insert(file_path.clone());
            }
        }
        if !file_paths.is_empty() {
            let project_dir = PathBuf::from(&args.output_dir).join(repo_name);
            let secs: u64 = match time_cache.get(repo_name).copied() {
                Some(secs) => {
                    if secs >= LIMIT_SECS {
                        continue;
                    }
                    if !project_dir.exists() {
                        let status = clone_repo(&row.clone_url, &project_dir);
                        if !status.success() {
                            eprintln!("Git clone failed for repo: {}", row.clone_url);
                            continue;
                        }
                    }
                    secs
                }
                None => {
                    if !project_dir.exists() {
                        let status = clone_repo(&row.clone_url, &project_dir);
                        if !status.success() {
                            eprintln!("Git clone failed for repo: {}", row.clone_url);
                            continue;
                        }
                    }
                    let start = Instant::now();
                    let st = Command::new("./java_autoql.sh")
                        .args([repo_name, project_dir.to_str().unwrap()])
                        .status();
                    let ok = matches!(st, Ok(s) if s.success());
                    let elapsed = start.elapsed().as_secs();
                    let effective = if ok { elapsed } else { 999999 };
                    let _ = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(time_cache_path)
                        .and_then(|mut f| {
                            use std::io::Write;
                            writeln!(f, "{} {}", repo_name, effective)
                        });

                    time_cache.insert(repo_name.to_string(), effective);
                    effective
                }
            };

            if secs >= LIMIT_SECS {
                eprintln!(
                    "Repo {} too slow ({}s), removing {}",
                    repo_name,
                    secs,
                    project_dir.to_str().unwrap()
                );
                let _ = fs::remove_dir_all(&project_dir);
                continue;
            }
            count += file_paths.len();
            println!(
                "Accepted repo: {}, files found: {}, real time: {}s, cumulative count: {}",
                row.full_name,
                file_paths.len(),
                secs,
                count
            );
        }
        if count >= args.file_num {
            break;
        }
    }
    let status = Command::new("python")
        .current_dir("../")
        .args([
            "run_rm_project_call_function.py",
            "--all",
            "--cwe",
            args.cwe.as_str(),
            "--one-fn-per-file",
        ])
        .status()
        .expect("failed to execute python script");
    if !status.success() {
        eprintln!("run_rm_project_call_function.py execute failed.");
    }
    let status = Command::new("python")
        .current_dir("../")
        .args(["rename_folders.py"])
        .status()
        .expect("failed to execute python script");
    if !status.success() {
        eprintln!("rename_folder.py execute failed.");
    }
    println!("finish to found and download repos.");
}