use itertools::Itertools;
use pcap::Capture;
use sscanf;
use std::collections::HashMap;

const INVERSE_MICRO: u64 = 1000000; // 10の6乗マイクロ秒を戻すために掛ける定数

fn main() {
    let mut cap = match Capture::from_file("test.pcapng") {
        Err(e) => {
            println!("failed to open pcap file: {}", e);
            std::process::exit(exitcode::IOERR);
        }
        Ok(c) => c,
    };

    let fillter_src_mac = to_mac_u8list("3c:22:fb:2c:7d:25".to_string());

    // パケット長の分布を保存するmap
    let mut packet_len_distribution = HashMap::new();
    let mut arrival_interval_distribution = HashMap::new();

    let mut prev_arrival = 0;

    while let Ok(packet) = cap.next() {
        // 上りパケットと下りパケットを区別するためEthernetフレームのsource MACアドレスを読み出してフィルタする。
        // ブロードキャストアドレスを考えるとsource MACアドレスで判断する方が良い。
        // pcapで見れるデータにプリアンブルは含まれていない。
        if packet.data.get(6..=11).unwrap() != fillter_src_mac {
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
            // 10年先を考えてもu64の範囲でオーバーフローすることなく計算できる。
            let arrival =
                packet.header.ts.tv_sec as u64 * INVERSE_MICRO + packet.header.ts.tv_usec as u64;

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
