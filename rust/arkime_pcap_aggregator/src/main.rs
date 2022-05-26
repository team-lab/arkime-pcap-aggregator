use chrono::prelude::*;
use clap::Parser;
use itertools::Itertools;
use pcap::Capture;
use sscanf;
use std::collections::HashMap;
use std::fs;
use std::io::BufWriter;
use std::io::Write;

extern crate regex;

use regex::Regex;

const INVERSE_MICRO: u64 = 1000000; // 10の6乗マイクロ秒を戻すために掛ける定数

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // フィルタするmacアドレス
    #[clap(long)]
    src_mac: String,

    // 対象とするパケットの開始時刻
    #[clap(long)]
    first: String,

    // 対象とするパケットの終了時刻
    #[clap(long)]
    last: String,

    // pcapファイルを検査する対象ディレクトリ
    #[clap(long, default_value = "/var/large-store/arkime/raw/")]
    search_path: String,
}

fn main() {
    let args = Args::parse();

    let fillter_src_mac = to_mac_u8list(args.src_mac.to_string());

    let first_datetime = match DateTime::parse_from_rfc3339(&args.first) {
        Err(_) => {
            eprintln!(
                "an invalid datetime format in `first` param: {}",
                args.first
            );
            std::process::exit(exitcode::CONFIG);
        }
        Ok(d) => d,
    };

    let first_micro_sec = first_datetime.timestamp() as u64 * INVERSE_MICRO;

    let last_datetime = match DateTime::parse_from_rfc3339(&args.last) {
        Err(_) => {
            eprintln!("an invalid datetime format in `last` param: {}", args.last);
            std::process::exit(exitcode::CONFIG);
        }
        Ok(d) => d,
    };

    let last_micro_sec = (last_datetime.timestamp() as u64 + 1) * INVERSE_MICRO - 1;

    let dirs = match fs::read_dir(&args.search_path) {
        Err(e) => {
            eprintln!(
                "failed to read directory: {}, reason: {}",
                args.search_path, e
            );
            std::process::exit(exitcode::IOERR);
        }
        Ok(d) => d,
    };

    // ".../localhost-220508-00001297.pcap"のようなファイル名を想定
    let re = Regex::new(r"/.+-(\d{6})-(\d{8})\.pcap$").unwrap();

    #[derive(Debug)]
    struct FileEntry {
        filename: String,
        fileid: u32,
        pcap_date: chrono::NaiveDate,
    }
    let mut pcap_list: Vec<FileEntry> = dirs
        .filter_map(|r| r.ok())
        .map(|d| {
            let path_str = d.path().into_os_string().into_string().unwrap();
            let cap_option = re.captures(&path_str);
            if cap_option.is_none() || cap_option.as_ref().unwrap().len() != 3 {
                return None::<FileEntry>;
            }
            let cap = cap_option.unwrap();

            let pcap_native_date = NaiveDate::parse_from_str(&cap[1], "%y%m%d").unwrap();
            Some(FileEntry {
                filename: path_str.clone(),
                fileid: cap[2].parse().unwrap(),
                pcap_date: pcap_native_date,
            })
        })
        .filter(|o| o.is_some())
        .map(|o| o.unwrap())
        .collect();

    if pcap_list.len() == 0 {
        eprintln!("there are no pcap files to process; exit.");
        std::process::exit(exitcode::OK);
    }

    pcap_list.sort_by(|a, b| a.fileid.partial_cmp(&b.fileid).unwrap());

    // 前日の日付のファイルに一部集計対象のパケットが含まれている可能性があり、読み出し始めるファイルのindex
    let mut read_first_index = 0;
    // pcapの読み出しを終えるファイルのindex
    let mut read_last_index = pcap_list.len() - 1;
    {
        let first_naive_date = first_datetime.naive_local().date();
        let last_naive_date = last_datetime.naive_local().date();
        let mut searching_first_index = true;
        for (i, e) in pcap_list.iter().enumerate() {
            if searching_first_index {
                if e.pcap_date < first_naive_date {
                    continue;
                } else {
                    read_first_index = match i.checked_sub(1) {
                        Some(i) => i,
                        None => 0,
                    };
                    searching_first_index = false;
                }
            } else {
                if e.pcap_date <= last_naive_date {
                    continue;
                } else {
                    read_last_index = match i.checked_sub(1) {
                        Some(i) => i,
                        None => 0,
                    };
                    break;
                }
            }
        }
    }

    // パケット長の分布を保存するmap
    let mut packet_len_distribution = HashMap::new();
    let mut arrival_interval_distribution = HashMap::new();

    let mut prev_arrival = 0;

    'pacp_read_loop: for path in pcap_list[read_first_index..=read_last_index]
        .iter()
        .map(|e| &e.filename)
    {
        eprintln!("read from {:?}", path);

        let mut cap = match Capture::from_file(path) {
            Err(e) => {
                eprintln!(
                    "failed to open pcap file; skip this file: {}, reason: {}",
                    path, e
                );
                continue;
            }
            Ok(c) => c,
        };

        // パケットごとのループ
        while let Ok(packet) = cap.next() {
            // 上りパケットと下りパケットを区別するためEthernetフレームのsource MACアドレスを読み出してフィルタする。
            // ブロードキャストアドレスを考えるとsource MACアドレスで判断する方が良い。
            // pcapで見れるデータにプリアンブルは含まれていない。
            if packet.data.get(6..=11).unwrap() != fillter_src_mac {
                continue;
            }

            // パケットの到着時刻をマイクロ秒で表す
            // 10年先を考えてもu64の範囲でオーバーフローすることなく計算できる。
            let arrival =
                packet.header.ts.tv_sec as u64 * INVERSE_MICRO + packet.header.ts.tv_usec as u64;
            // 集計開始時刻よりも到着パケットのタイムスタンプが早いなら読み飛ばす。
            if arrival < first_micro_sec {
                continue;
            }
            if arrival > last_micro_sec {
                // 集計終了時刻よりも到着パケットのタイムスタンプが遅いなら、それ以降のパケットを読み取っても意味がない。直ちに終了する。
                break 'pacp_read_loop;
            }

            // パケット長の処理
            {
                let len_count = packet_len_distribution
                    .entry(packet.header.len)
                    .or_insert(0);
                *len_count += 1;
            }

            // パケット到着間隔の処理
            {
                if prev_arrival != 0 {
                    let arrival_delta: u64 = arrival - prev_arrival;

                    let delta_count = arrival_interval_distribution
                        .entry(arrival_delta)
                        .or_insert(0);
                    *delta_count += 1;
                }
                prev_arrival = arrival;
            }
        }
    }

    // 結果をファイルに書き出し始める
    {
        let len_distr_filename = format!(
            "{}-{}--{}-len-distr.tsv",
            to_mac_file_string(&fillter_src_mac),
            first_datetime.format("%Y%m%dT%H%M%S").to_string(),
            last_datetime.format("%Y%m%dT%H%M%S").to_string()
        );

        match fs::File::create(&len_distr_filename) {
            Ok(f) => {
                let mut writer = BufWriter::new(f);
                for (len, count) in packet_len_distribution.iter().sorted() {
                    if let Err(e) = writer.write(format!("{}\t{}\n", len, count).as_bytes()) {
                        eprintln!("file write error: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "failed to create an output file: {}, reason: {}",
                    &len_distr_filename, e
                );
                eprintln!("fallback to stdout output");
                for (len, count) in packet_len_distribution.iter().sorted() {
                    println!("{}\t{}", len, count);
                }
            }
        }

        let arrival_interval_distr_filename = format!(
            "{}-{}--{}-arrival-interval-distr.tsv",
            to_mac_file_string(&fillter_src_mac),
            first_datetime.format("%Y%m%dT%H%M%S").to_string(),
            last_datetime.format("%Y%m%dT%H%M%S").to_string()
        );

        match fs::File::create(&arrival_interval_distr_filename) {
            Ok(f) => {
                let mut writer = BufWriter::new(f);
                for (delta, count) in arrival_interval_distribution.iter().sorted() {
                    if let Err(e) = writer.write(format!("{}\t{}\n", delta, count).as_bytes()) {
                        eprintln!("file write error: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "failed to create an output file: {}, reason: {}",
                    &arrival_interval_distr_filename, e
                );
                eprintln!("fallback to stdout output");
                for (delta, count) in arrival_interval_distribution.iter().sorted() {
                    println!("{}\t{}", delta, count);
                }
            }
        }
    }
}

// macアドレスを人間が読み易い形で返す
fn to_mac_string(mac: &[u8]) -> String {
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn to_mac_file_string(mac: &[u8]) -> String {
    format!(
        "{:x}{:x}{:x}{:x}{:x}{:x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// 人間が入力したStringをプログラムで処理しやすいbyte表現に変換して返す
fn to_mac_u8list(str: String) -> [u8; 6] {
    match sscanf::scanf!(str, "{u8:x}:{u8:x}:{u8:x}:{u8:x}:{u8:x}:{u8:x}") {
        Err(_) => [0, 0, 0, 0, 0, 0],
        Ok(c) => [c.0, c.1, c.2, c.3, c.4, c.5],
    }
}
