use chrono::prelude::*;
use clap::Parser;
use itertools::Itertools;
use pcap::Capture;
use sscanf;
use std::collections::HashMap;
use std::fs;

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
            println!(
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
            println!("an invalid datetime format in `last` param: {}", args.last);
            std::process::exit(exitcode::CONFIG);
        }
        Ok(d) => d,
    };

    let last_micro_sec = (last_datetime.timestamp() as u64 + 1) * INVERSE_MICRO - 1;

    let focus_time_range = first_micro_sec..last_micro_sec;

    let dirs = match fs::read_dir(&args.search_path) {
        Err(e) => {
            println!(
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

            println!("path_str: {}", path_str);
            println!("opt: {:?}", cap_option);

            if cap_option.is_none() || cap_option.as_ref().unwrap().len() != 3 {
                return None::<FileEntry>;
            }
            let cap = cap_option.unwrap();

            let pcap_native_date = NaiveDate::parse_from_str(&cap[1], "%y%m%d").unwrap();
            //let pcap_date = FixedOffset::east(9 * 3600).from_local_datetime(&pcap_native_date).unwrap();
            Some(FileEntry {
                filename: path_str.clone(),
                fileid: cap[2].parse().unwrap(),
                pcap_date: pcap_native_date,
            })
        })
        .filter(|o| o.is_some())
        .map(|o| o.unwrap())
        .collect();

    pcap_list.sort_by(|a, b| a.fileid.partial_cmp(&b.fileid).unwrap());
    println!("pcap_list dump: {:?}", pcap_list);

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
                if e.pcap_date > first_naive_date {
                    continue;
                } else {
                    read_first_index = i - 1;
                    searching_first_index = false;
                }
            } else {
                if e.pcap_date < last_naive_date {
                    continue;
                } else {
                    read_last_index = i - 1;
                    break;
                }
            }
        }
    }

    // パケット長の分布を保存するmap
    let mut packet_len_distribution = HashMap::new();
    let mut arrival_interval_distribution = HashMap::new();

    let mut prev_arrival = 0;

    // pcapごとの大きなループ
    for path in pcap_list[read_first_index..read_last_index]
        .iter()
        .map(|e| &e.filename)
    {
        println!("read from {:?}", path);

        let mut cap = match Capture::from_file(path) {
            Err(e) => {
                println!(
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
            if !focus_time_range.contains(&arrival) {
                // 注目している時間範囲内に入っていないなら、処理しない。
                continue;
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

    for (len, count) in packet_len_distribution.iter().sorted() {
        println!("{}\t{}", len, count);
    }
    for (delta, count) in arrival_interval_distribution.iter().sorted() {
        println!("{}\t{}", delta, count);
    }
}

// macアドレスを人間が読み易い形で返す
fn to_mac_string(mac: &[u8]) -> String {
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
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
