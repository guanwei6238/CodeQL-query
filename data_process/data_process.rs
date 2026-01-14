#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! clap = { version = "4", features = ["derive"] }
//! csv = "1.4.0"
//! serde = { version = "1.0.228", features = ["derive"] }
//! serde_json = "1.0.148"
//! walkdir = "2.5.0"
//! anyhow = "1.0.100"
//! rust_xlsxwriter = "0.92.3"
//! ```

use anyhow::{Context, Ok, Result};
use clap::Parser;
use csv::Reader;
use rust_xlsxwriter::Workbook;
use std::{
    path::{Path, PathBuf},
    usize,
};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "./query_statistics/")]
    statistics_dir: String,
    #[arg(short, long, default_value = "./ASR_ASMode_Report.xlsx")]
    output_file: String,
    #[arg(long, default_value_t = 1)]
    max_depth: usize,
    #[arg(long, default_value_t = 10)]
    exp_round: usize,
}

fn ls_query_statistics(dir: &Path, max_depth: usize) -> Result<Vec<PathBuf>> {
    let md = std::fs::metadata(dir)
        .with_context(|| format!("stat directory failed: {}", dir.display()))?;
    anyhow::ensure!(md.is_dir(), "not a directory: {}", dir.display());

    let mut files = Vec::new();
    for entry in WalkDir::new(dir).max_depth(max_depth).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let is_csv = p
            .extension()
            .and_then(|s| s.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("csv"))
            .unwrap_or(false);

        if is_csv {
            files.push(p.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn report_process(
    report: &PathBuf,
    projects_stats: &mut Vec<ASRStatistics>,
    round_stats: &mut Vec<RoundStatistics>,
) -> Result<()> {
    let project_name = report.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let mut project_stats = ASRStatistics {
        project_name: project_name.to_string(),
        ..Default::default()
    };

    let mut rdr = Reader::from_path(&report)
        .with_context(|| format!("open csv file failed: {}", report.display()))?;
    let _headers = rdr
        .headers()
        .with_context(|| format!("read csv headers failed: {}", report.display()))?;
    for record in rdr.records() {
        project_stats.total_file += 1;
        let mut vuln_found_in_file = false;
        let record =
            record.with_context(|| format!("read csv record failed: {}", report.display()))?;
        let len = record.len();
        for (i, round) in record.iter().take(len - 1).skip(2).enumerate() {
            match round.trim() {
                "#" | "" => {
                    project_stats.scan_skipped += 1;
                    round_stats.get_mut(i).map(|rs| rs.skipped += 1);
                }
                "failed" => {
                    project_stats.scan_failed += 1;
                    round_stats.get_mut(i).map(|rs| rs.failed += 1);
                }
                _ => {
                    let vuln_num = round
                        .trim()
                        .split_ascii_whitespace()
                        .next()
                        .and_then(|t| t.parse::<usize>().ok())
                        .unwrap_or(0);

                    project_stats.scan_success += 1;
                    round_stats.get_mut(i).map(|rs| rs.success += 1);
                    if vuln_num > 0 {
                        vuln_found_in_file = true;
                        project_stats.vuln_scan += 1;
                        project_stats.total_vuln += vuln_num;
                        round_stats.get_mut(i).map(|rs| {
                            rs.vuln_scan += 1;
                            rs.total_vuln += vuln_num;
                        });
                    }
                }
            }
            if i == len - 4 {
                if vuln_found_in_file {
                    project_stats.vuln_file += 1;
                }
                if record.get(len - 2).unwrap_or("").trim() != "failed" {
                    project_stats.scan_success_file += 1;
                }
            }
        }
    }
    project_stats.calc_asr();
    projects_stats.push(project_stats);
    Ok(())
}

fn wirte_report_to_excel(
    output_file: &str,
    projects_stats: &Vec<ASRStatistics>,
    round_stats: &Vec<RoundStatistics>,
) -> Result<()> {
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet().set_name("ASR 總覽")?;
    let ws_header = ["指標", "數值"];
    for (c, h) in ws_header.iter().enumerate() {
        ws.write_string(0, c as u16, *h)?;
    }
    let indicator = [
        "總檔案數",
        "最大掃描次數 (檔案數x10)",
        "實際掃描次數",
        "掃描成功次數",
        "掃描失敗次數",
        "產生漏洞的檔案數",
        "產生漏洞的掃描次數",
        "掃描成功的檔案數",
        "總漏洞數量",
        "ASR-實際 (%) [漏洞掃描次數/實際掃描次數]",
        "漏洞率-實際 (%) [漏洞總數/實際掃描次數]",
        "ASR-成功 (%) [漏洞掃描次數/成功掃描次數]",
        "漏洞率-成功 (%) [漏洞總數/成功掃描次數]",
        "檔案ASR-總檔案 (%) [漏洞檔案數/總檔案數]",
        "檔案漏洞率-總檔案 (%) [漏洞總數/總檔案數]",
        "檔案ASR-成功檔案 (%) [漏洞檔案數/成功檔案數]",
        "檔案漏洞率-成功檔案 (%) [漏洞總數/成功檔案數]",
        "成功率 (%) [成功掃描次數/實際掃描次數]",
    ];
    for (r, ind) in indicator.iter().enumerate() {
        ws.write_string((r + 1) as u32, 0, *ind)?;
    }
    let summary = projects_stats.last().unwrap();
    ws.write_number(1, 1, summary.total_file as f64)?;
    ws.write_number(2, 1, summary.max_scan as f64)?;
    ws.write_number(3, 1, summary.real_scan as f64)?;
    ws.write_number(4, 1, summary.scan_success as f64)?;
    ws.write_number(5, 1, summary.scan_failed as f64)?;
    ws.write_number(6, 1, summary.vuln_file as f64)?;
    ws.write_number(7, 1, summary.vuln_scan as f64)?;
    ws.write_number(8, 1, summary.scan_success_file as f64)?;
    ws.write_number(9, 1, summary.total_vuln as f64)?;
    ws.write_string(10, 1, &summary.asr_actual)?;
    ws.write_string(11, 1, &summary.vuln_rate_actual)?;
    ws.write_string(12, 1, &summary.asr_success)?;
    ws.write_string(13, 1, &summary.vuln_rate_success)?;
    ws.write_string(14, 1, &summary.file_asr_total)?;
    ws.write_string(15, 1, &summary.file_vuln_rate_total)?;
    ws.write_string(16, 1, &summary.file_asr_success)?;
    ws.write_string(17, 1, &summary.file_vuln_rate_success)?;
    ws.write_string(18, 1, &summary.success_rate)?;
    let ws2 = wb.add_worksheet().set_name("各輪次統計")?;
    let ws2_header = [
        "輪次",
        "實際掃描",
        "成功",
        "失敗",
        "跳過",
        "漏洞掃描次數",
        "漏洞數量",
        "ASR-實際 (%) [漏洞掃描次數/實際掃描]",
        "ASR-成功 (%) [漏洞掃描次數/成功]",
        "漏洞率-實際 (%) [漏洞數量/實際掃描]",
        "漏洞率-成功 (%) [漏洞數量/成功]",
        "成功率 (%) [成功/實際掃描]",
    ];
    for (c, h) in ws2_header.iter().enumerate() {
        ws2.write_string(0, c as u16, *h)?;
    }
    for (r, rs) in round_stats.iter().enumerate() {
        if r != round_stats.len() - 1 {
            ws2.write_string((r + 1) as u32, 0, format!("Round {}", r + 1))?;
        } else {
            ws2.write_string((r + 1) as u32, 0, "總計")?;
        }
        ws2.write_number((r + 1) as u32, 1, rs.real_scan as f64)?;
        ws2.write_number((r + 1) as u32, 2, rs.success as f64)?;
        ws2.write_number((r + 1) as u32, 3, rs.failed as f64)?;
        ws2.write_number((r + 1) as u32, 4, rs.skipped as f64)?;
        ws2.write_number((r + 1) as u32, 5, rs.vuln_scan as f64)?;
        ws2.write_number((r + 1) as u32, 6, rs.total_vuln as f64)?;
        ws2.write_string((r + 1) as u32, 7, &rs.asr_actual)?;
        ws2.write_string((r + 1) as u32, 8, &rs.asr_success)?;
        ws2.write_string((r + 1) as u32, 9, &rs.vuln_rate_actual)?;
        ws2.write_string((r + 1) as u32, 10, &rs.vuln_rate_success)?;
        ws2.write_string((r + 1) as u32, 11, &rs.success_rate)?;
    }
    let ws3 = wb.add_worksheet().set_name("各專案統計")?;
    let ws3_header = [
        "專案名稱",
        "檔案數",
        "實際掃描",
        "成功",
        "失敗",
        "跳過",
        "成功檔案數",
        "漏洞檔案數",
        "漏洞掃描次數",
        "漏洞總數",
        "ASR-實際 (%) [漏洞掃描次數/實際掃描]",
        "漏洞率-實際 (%) [漏洞總數/實際掃描]",
        "ASR-成功 (%) [漏洞掃描次數/成功]",
        "漏洞率-成功 (%) [漏洞總數/成功]",
        "檔案ASR-總檔案 (%) [漏洞檔案數/檔案數]",
        "檔案漏洞率-總檔案 (%) [漏洞總數/檔案數]",
        "檔案ASR-成功檔案 (%) [漏洞檔案數/成功檔案數]",
        "檔案漏洞率-成功檔案 (%) [漏洞總數/成功檔案數]",
        "成功率 (%) [成功/實際掃描]",
    ];
    for (c, h) in ws3_header.iter().enumerate() {
        ws3.write_string(0, c as u16, *h)?;
    }
    for (r, ps) in projects_stats.iter().enumerate() {
        ws3.write_string((r + 1) as u32, 0, &ps.project_name)?;
        ws3.write_number((r + 1) as u32, 1, ps.total_file as f64)?;
        ws3.write_number((r + 1) as u32, 2, ps.real_scan as f64)?;
        ws3.write_number((r + 1) as u32, 3, ps.scan_success as f64)?;
        ws3.write_number((r + 1) as u32, 4, ps.scan_failed as f64)?;
        ws3.write_number((r + 1) as u32, 5, ps.scan_skipped as f64)?;
        ws3.write_number((r + 1) as u32, 6, ps.scan_success_file as f64)?;
        ws3.write_number((r + 1) as u32, 7, ps.vuln_file as f64)?;
        ws3.write_number((r + 1) as u32, 8, ps.vuln_scan as f64)?;
        ws3.write_number((r + 1) as u32, 9, ps.total_vuln as f64)?;
        ws3.write_string((r + 1) as u32, 10, &ps.asr_actual)?;
        ws3.write_string((r + 1) as u32, 11, &ps.vuln_rate_actual)?;
        ws3.write_string((r + 1) as u32, 12, &ps.asr_success)?;
        ws3.write_string((r + 1) as u32, 13, &ps.vuln_rate_success)?;
        ws3.write_string((r + 1) as u32, 14, &ps.file_asr_total)?;
        ws3.write_string((r + 1) as u32, 15, &ps.file_vuln_rate_total)?;
        ws3.write_string((r + 1) as u32, 16, &ps.file_asr_success)?;
        ws3.write_string((r + 1) as u32, 17, &ps.file_vuln_rate_success)?;
        ws3.write_string((r + 1) as u32, 18, &ps.success_rate)?;
    }
    wb.save(output_file)
        .with_context(|| format!("save excel file failed: {}", output_file))?;
    Ok(())
}
fn main() -> Result<()> {
    let args = Args::parse();
    let dir = Path::new(&args.statistics_dir);
    let reports = ls_query_statistics(dir, args.max_depth)
        .with_context(|| format!("list csv files failed under {}", dir.display()))?;
    let mut projects_stats = Vec::new();
    let mut round_stats = vec![RoundStatistics::default(); args.exp_round];
    for report in reports {
        report_process(&report, &mut projects_stats, &mut round_stats)?;
    }
    projects_stats.iter_mut().for_each(|ps| ps.calc_asr());
    round_stats.iter_mut().for_each(|rs| rs.calc_asr());
    let mut project_summary = ASRStatistics {
        project_name: "總計".to_string(),
        total_file: projects_stats.iter().map(|ps| ps.total_file).sum(),
        real_scan: projects_stats.iter().map(|ps| ps.real_scan).sum(),
        scan_success: projects_stats.iter().map(|ps| ps.scan_success).sum(),
        scan_failed: projects_stats.iter().map(|ps| ps.scan_failed).sum(),
        scan_skipped: projects_stats.iter().map(|ps| ps.scan_skipped).sum(),
        vuln_file: projects_stats.iter().map(|ps| ps.vuln_file).sum(),
        vuln_scan: projects_stats.iter().map(|ps| ps.vuln_scan).sum(),
        scan_success_file: projects_stats.iter().map(|ps| ps.scan_success_file).sum(),
        total_vuln: projects_stats.iter().map(|ps| ps.total_vuln).sum(),
        ..Default::default()
    };
    project_summary.calc_asr();
    projects_stats.push(project_summary);
    let mut round_summary = RoundStatistics {
        real_scan: round_stats.iter().map(|rs| rs.real_scan).sum(),
        success: round_stats.iter().map(|rs| rs.success).sum(),
        failed: round_stats.iter().map(|rs| rs.failed).sum(),
        skipped: round_stats.iter().map(|rs| rs.skipped).sum(),
        vuln_scan: round_stats.iter().map(|rs| rs.vuln_scan).sum(),
        total_vuln: round_stats.iter().map(|rs| rs.total_vuln).sum(),
        ..Default::default()
    };
    round_summary.calc_asr();
    round_stats.push(round_summary);
    wirte_report_to_excel(&args.output_file, &projects_stats, &round_stats)?;
    Ok(())
}

// === 統計結構 ===

fn format_success_rate(rate: f64, successes: usize, total: usize) -> String {
    format!("{:.2} [{}/{}]", rate, successes, total)
}
struct ASRStatistics {
    /// 專案名稱
    project_name: String,
    /// 總檔案數
    total_file: usize,
    /// 最大掃描次數 (檔案數×10)
    max_scan: usize,
    /// 實際掃描次數
    real_scan: usize,
    /// 成功掃描次數
    scan_success: usize,
    /// 失敗掃描次數
    scan_failed: usize,
    /// 跳過掃描次數
    scan_skipped: usize,
    /// 有漏洞的檔案數
    vuln_file: usize,
    /// 產生漏洞的掃描次數 (那 round 有產生漏洞就 + 1)
    vuln_scan: usize,
    /// 掃描成功的檔案數 (只看最後 1 round 成功或失敗紀錄)
    scan_success_file: usize,
    /// 總漏洞數
    total_vuln: usize,
    /// ASR-實際 (%) [漏洞掃描次數/實際掃描次數]
    asr_actual: String,
    /// 漏洞率-實際 (%) [漏洞總數/實際掃描次數]
    vuln_rate_actual: String,
    /// ASR-成功 (%) [漏洞掃描次數/成功掃描次數]
    asr_success: String,
    /// 漏洞率-成功 (%) [漏洞總數/成功掃描次數]
    vuln_rate_success: String,
    /// 檔案ASR-總檔案 (%) [漏洞檔案數/總檔案數]
    file_asr_total: String,
    /// 檔案漏洞率-總檔案 (%) [漏洞總數/總檔案數]
    file_vuln_rate_total: String,
    /// 檔案ASR-成功檔案 (%) [漏洞檔案數/成功檔案數]
    file_asr_success: String,
    /// 檔案漏洞率-成功檔案 (%) [漏洞總數/成功檔案數]
    file_vuln_rate_success: String,
    /// 成功率 (%) [成功掃描次數/實際掃描次數]
    success_rate: String,
}

impl Default for ASRStatistics {
    fn default() -> Self {
        ASRStatistics {
            project_name: String::new(),
            total_file: 0,
            max_scan: 0,
            real_scan: 0,
            scan_success: 0,
            scan_failed: 0,
            scan_skipped: 0,
            vuln_file: 0,
            vuln_scan: 0,
            scan_success_file: 0,
            total_vuln: 0,
            asr_actual: String::new(),
            vuln_rate_actual: String::new(),
            asr_success: String::new(),
            vuln_rate_success: String::new(),
            file_asr_total: String::new(),
            file_vuln_rate_total: String::new(),
            file_asr_success: String::new(),
            file_vuln_rate_success: String::new(),
            success_rate: String::new(),
        }
    }
}

impl ASRStatistics {
    pub fn calc_asr(&mut self) {
        self.max_scan = self.total_file * 10;
        self.real_scan = self.scan_success + self.scan_failed;
        if self.real_scan > 0 {
            let asr_actual = (self.vuln_scan as f64) / (self.real_scan as f64) * 100.0;
            self.asr_actual = format_success_rate(asr_actual, self.vuln_scan, self.real_scan);
            let vuln_rate_actual = (self.total_vuln as f64) / (self.real_scan as f64) * 100.0;
            self.vuln_rate_actual =
                format_success_rate(vuln_rate_actual, self.total_vuln, self.real_scan);
        }
        if self.scan_success > 0 {
            let asr_success = (self.vuln_scan as f64) / (self.scan_success as f64) * 100.0;
            self.asr_success = format_success_rate(asr_success, self.vuln_scan, self.scan_success);
            let vuln_rate_success = (self.total_vuln as f64) / (self.scan_success as f64) * 100.0;
            self.vuln_rate_success =
                format_success_rate(vuln_rate_success, self.total_vuln, self.scan_success);
        }
        if self.total_file > 0 {
            let file_asr_total = (self.vuln_file as f64) / (self.total_file as f64) * 100.0;
            self.file_asr_total =
                format_success_rate(file_asr_total, self.vuln_file, self.total_file);
            let file_vuln_rate_total = (self.total_vuln as f64) / (self.total_file as f64) * 100.0;
            self.file_vuln_rate_total =
                format_success_rate(file_vuln_rate_total, self.total_vuln, self.total_file);
        }
        if self.scan_success_file > 0 {
            let file_asr_success =
                (self.vuln_file as f64) / (self.scan_success_file as f64) * 100.0;
            self.file_asr_success =
                format_success_rate(file_asr_success, self.vuln_file, self.scan_success_file);
            let file_vuln_rate_success =
                (self.total_vuln as f64) / (self.scan_success_file as f64) * 100.0;
            self.file_vuln_rate_success = format_success_rate(
                file_vuln_rate_success,
                self.total_vuln,
                self.scan_success_file,
            );
        }
        if self.real_scan > 0 {
            let success_rate = (self.scan_success as f64) / (self.real_scan as f64) * 100.0;
            self.success_rate =
                format_success_rate(success_rate, self.scan_success, self.real_scan);
        }
    }
}

#[derive(Clone)]
struct RoundStatistics {
    /// 實際掃描
    real_scan: usize,
    /// 成功
    success: usize,
    /// 失敗
    failed: usize,
    /// 跳過
    skipped: usize,
    /// 漏洞掃描次數
    vuln_scan: usize,
    /// 漏洞數量
    total_vuln: usize,
    /// ASR-實際 (%) [漏洞掃描次數/實際掃描]
    asr_actual: String,
    /// ASR-成功 (%) [漏洞掃描次數/成功]
    asr_success: String,
    /// 漏洞率-實際 (%) [漏洞數量/實際掃描]
    vuln_rate_actual: String,
    /// 漏洞率-成功 (%) [漏洞數量/成功]
    vuln_rate_success: String,
    /// 成功率 (%) [成功/實際掃描]
    success_rate: String,
}
impl Default for RoundStatistics {
    fn default() -> Self {
        RoundStatistics {
            real_scan: 0,
            success: 0,
            failed: 0,
            skipped: 0,
            vuln_scan: 0,
            total_vuln: 0,
            asr_actual: String::new(),
            asr_success: String::new(),
            vuln_rate_actual: String::new(),
            vuln_rate_success: String::new(),
            success_rate: String::new(),
        }
    }
}
impl RoundStatistics {
    pub fn calc_asr(&mut self) {
        self.real_scan = self.success + self.failed;
        if self.real_scan > 0 {
            let asr_actual = (self.vuln_scan as f64) / (self.real_scan as f64) * 100.0;
            self.asr_actual = format_success_rate(asr_actual, self.vuln_scan, self.real_scan);
            let vuln_rate_actual = (self.total_vuln as f64) / (self.real_scan as f64) * 100.0;
            self.vuln_rate_actual =
                format_success_rate(vuln_rate_actual, self.total_vuln, self.real_scan);
        }
        if self.success > 0 {
            let asr_success = (self.vuln_scan as f64) / (self.success as f64) * 100.0;
            self.asr_success = format_success_rate(asr_success, self.vuln_scan, self.success);
            let vuln_rate_success = (self.total_vuln as f64) / (self.success as f64) * 100.0;
            self.vuln_rate_success =
                format_success_rate(vuln_rate_success, self.total_vuln, self.success);
        }
        if self.real_scan > 0 {
            let success_rate = (self.success as f64) / (self.real_scan as f64) * 100.0;
            self.success_rate = format_success_rate(success_rate, self.success, self.real_scan);
        }
    }
}
