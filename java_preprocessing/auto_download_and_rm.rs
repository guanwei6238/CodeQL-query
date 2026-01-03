#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! clap = { version = "4", features = ["derive"] }
//! csv = "1.4.0"
//! serde = { version = "1.0.228", features = ["derive"] }
//! serde_json = "1.0.148"
//! ```
use clap::Parser;
use csv::Reader;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    process::Command,
};

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
fn main() {
    let args = Args::parse();
    let cwe = format!("CWE-{}", args.cwe);
    let file = File::open(&args.csv).expect("Cannot open CSV file");
    let mut rdr = Reader::from_reader(file);
    let mut count = 0;
    for res in rdr.deserialize::<Row>() {
        let row = res.expect("Cannot deserialize row");
        let repo_name = row
            .full_name
            .split("/")
            .nth(1)
            .expect("repo name not found.");
        let json_path = format!("./java_query_output/{}/{}.json", repo_name, repo_name);
        let json_text = fs::read_to_string(&json_path).expect("Cannot read JSON file");
        let json_value: Value = match serde_json::from_str(&json_text) {
            Ok(val) => val,
            Err(_) => continue,
        };
        let mut found = false;
        let mut file_paths = BTreeSet::new();
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
                found = true;
            }
        }
        if found {
            count += file_paths.len();
            println!(
                "Found repo: {}, total files found: {}, cumulative count: {}",
                row.full_name,
                file_paths.len(),
                count
            );
            let status = Command::new("git")
                .args([
                    "clone",
                    "--depth",
                    "1",
                    "--recurse-submodules",
                    &row.clone_url,
                    format!("{}/{}", args.output_dir, repo_name).as_str(),
                ])
                .status()
                .expect("failed to execute git clone");
            if !status.success() {
                eprintln!("Git clone failed for repo: {}", row.clone_url);
                continue;
            }
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
