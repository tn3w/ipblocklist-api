use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

const MAGIC: &[u8; 4] = b"IPBL";
const BLOCKLIST_URL: &str = "https://github.com/tn3w/IPBlocklist\
     /releases/latest/download/blocklist.bin";

struct Feed {
    name: Box<str>,
    score: f32,
    flags_mask: u32,
    cats_mask: u8,
}

struct Ranges4 {
    feed_idx: u16,
    ranges: Box<[(u32, u32)]>,
}

struct Ranges6 {
    feed_idx: u16,
    ranges: Box<[(u128, u128)]>,
}

struct Blocklist {
    timestamp: u32,
    flag_table: Box<[Box<str>]>,
    cat_table: Box<[Box<str>]>,
    feeds: Box<[Feed]>,
    ipv4: Box<[Ranges4]>,
    ipv6: Box<[Ranges6]>,
}

type State = Arc<RwLock<Option<Arc<Blocklist>>>>;

fn read_varint(c: &mut Cursor<&[u8]>) -> u128 {
    let mut result: u128 = 0;
    let mut shift = 0u32;
    let mut b = [0u8; 1];
    loop {
        c.read_exact(&mut b).unwrap();
        result |= ((b[0] & 0x7F) as u128) << shift;
        if b[0] & 0x80 == 0 {
            return result;
        }
        shift += 7;
    }
}

fn read_str(c: &mut Cursor<&[u8]>) -> Box<str> {
    let len = read_u8(c) as usize;
    let mut buf = vec![0u8; len];
    c.read_exact(&mut buf).unwrap();
    String::from_utf8(buf).unwrap().into_boxed_str()
}

fn read_u8(c: &mut Cursor<&[u8]>) -> u8 {
    let mut b = [0u8; 1];
    c.read_exact(&mut b).unwrap();
    b[0]
}

fn read_u16_le(c: &mut Cursor<&[u8]>) -> u16 {
    let mut b = [0u8; 2];
    c.read_exact(&mut b).unwrap();
    u16::from_le_bytes(b)
}

fn read_u32_le(c: &mut Cursor<&[u8]>) -> u32 {
    let mut b = [0u8; 4];
    c.read_exact(&mut b).unwrap();
    u32::from_le_bytes(b)
}

fn parse(data: &[u8]) -> Blocklist {
    let mut c = Cursor::new(data);

    let mut magic = [0u8; 4];
    c.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, MAGIC);
    assert_eq!(read_u8(&mut c), 2);

    let timestamp = read_u32_le(&mut c);

    let flag_count = read_u8(&mut c) as usize;
    let flag_table: Box<[Box<str>]> = (0..flag_count).map(|_| read_str(&mut c)).collect();

    let cat_count = read_u8(&mut c) as usize;
    let cat_table: Box<[Box<str>]> = (0..cat_count).map(|_| read_str(&mut c)).collect();

    let feed_count = read_u16_le(&mut c) as usize;
    let mut feeds = Vec::with_capacity(feed_count);
    let mut ipv4_feeds: Vec<Ranges4> = Vec::new();
    let mut ipv6_feeds: Vec<Ranges6> = Vec::new();

    for feed_idx in 0..feed_count {
        let name = read_str(&mut c);
        let score = (read_u8(&mut c) as f32 / 200.0) * (read_u8(&mut c) as f32 / 200.0);
        let flags_mask = read_u32_le(&mut c);
        let cats_mask = read_u8(&mut c);

        feeds.push(Feed {
            name,
            score,
            flags_mask,
            cats_mask,
        });

        let range_count = read_u32_le(&mut c) as usize;
        let mut v4: Vec<(u32, u32)> = Vec::new();
        let mut v6: Vec<(u128, u128)> = Vec::new();
        let mut start: u128 = 0;

        for _ in 0..range_count {
            start += read_varint(&mut c);
            let end = start + read_varint(&mut c);
            if end <= u32::MAX as u128 {
                v4.push((start as u32, end as u32));
            } else {
                v6.push((start, end));
            }
        }

        if !v4.is_empty() {
            ipv4_feeds.push(Ranges4 {
                feed_idx: feed_idx as u16,
                ranges: v4.into(),
            });
        }
        if !v6.is_empty() {
            ipv6_feeds.push(Ranges6 {
                feed_idx: feed_idx as u16,
                ranges: v6.into(),
            });
        }
    }

    Blocklist {
        timestamp,
        flag_table,
        cat_table,
        feeds: feeds.into(),
        ipv4: ipv4_feeds.into(),
        ipv6: ipv6_feeds.into(),
    }
}

fn range_contains<T: Ord + Copy>(ranges: &[(T, T)], target: T) -> bool {
    let idx = ranges.partition_point(|&(start, _)| start <= target);
    idx > 0 && target <= ranges[idx - 1].1
}

fn resolve_flags<'a>(table: &'a [Box<str>], mask: u32) -> Vec<&'a str> {
    (0..table.len())
        .filter(|&i| mask & (1 << i) != 0)
        .map(|i| &*table[i])
        .collect()
}

fn resolve_cats<'a>(table: &'a [Box<str>], mask: u8) -> Vec<&'a str> {
    (0..table.len())
        .filter(|&i| mask & (1 << i) != 0)
        .map(|i| &*table[i])
        .collect()
}

struct LookupResult<'a> {
    ip: String,
    max_score: f32,
    top_category: &'a str,
    categories: Vec<&'a str>,
    flags: Vec<&'a str>,
    feeds: Vec<&'a str>,
}

fn json_escape(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn json_str_array(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| json_escape(s)).collect();
    format!("[{}]", inner.join(","))
}

impl LookupResult<'_> {
    fn to_json(&self) -> String {
        format!(
            r#"{{"ip":{},"max_score":{:.4},"top_category":{},"categories":{},"flags":{},"feeds":{}}}"#,
            json_escape(&self.ip),
            self.max_score,
            json_escape(self.top_category),
            json_str_array(&self.categories),
            json_str_array(&self.flags),
            json_str_array(&self.feeds),
        )
    }
}

fn lookup<'a>(bl: &'a Blocklist, ip: IpAddr) -> LookupResult<'a> {
    let mut hits: Vec<(u16, f32)> = match ip {
        IpAddr::V4(v4) => {
            let target = u32::from(v4);
            bl.ipv4
                .iter()
                .filter(|r| range_contains(&r.ranges, target))
                .map(|r| (r.feed_idx, bl.feeds[r.feed_idx as usize].score))
                .collect()
        }
        IpAddr::V6(v6) => {
            let target = u128::from(v6);
            bl.ipv6
                .iter()
                .filter(|r| range_contains(&r.ranges, target))
                .map(|r| (r.feed_idx, bl.feeds[r.feed_idx as usize].score))
                .collect()
        }
    };
    hits.sort_unstable_by(|a, b| b.1.total_cmp(&a.1));

    let mut all_flags_mask: u32 = 0;
    let mut cat_counts: Vec<(&str, u16)> = Vec::new();
    let mut feed_names: Vec<&str> = Vec::new();

    for &(idx, _) in &hits {
        let feed = &bl.feeds[idx as usize];
        feed_names.push(&feed.name);
        all_flags_mask |= feed.flags_mask;
        for cat in resolve_cats(&bl.cat_table, feed.cats_mask) {
            if let Some(entry) = cat_counts.iter_mut().find(|e| e.0 == cat) {
                entry.1 += 1;
            } else {
                cat_counts.push((cat, 1));
            }
        }
    }

    let all_cats: Vec<&str> = cat_counts.iter().map(|e| e.0).collect();
    let max_score = hits.first().map(|h| h.1).unwrap_or(0.0);
    let top_category = cat_counts
        .iter()
        .max_by_key(|e| e.1)
        .map(|e| e.0)
        .unwrap_or("none");

    LookupResult {
        ip: ip.to_string(),
        max_score,
        top_category,
        categories: all_cats,
        flags: resolve_flags(&bl.flag_table, all_flags_mask),
        feeds: feed_names,
    }
}

fn download() -> Option<Vec<u8>> {
    eprintln!("downloading blocklist...");
    let output = std::process::Command::new("curl")
        .args(["-fsSL", BLOCKLIST_URL])
        .output()
        .ok()?;
    if !output.status.success() {
        eprintln!("curl failed: {}", output.status);
        return None;
    }
    eprintln!("loaded {} bytes", output.stdout.len());
    Some(output.stdout)
}

fn send_json(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn handle(mut stream: TcpStream, state: &State) {
    let mut reader = BufReader::new(&stream);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).is_err() {
        return;
    }

    let url = first_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();

    if url == "/health" {
        let guard = state.read().unwrap();
        let body = match guard.as_ref() {
            Some(bl) => format!(r#"{{"status":"ok","timestamp":{}}}"#, bl.timestamp),
            None => r#"{"status":"loading"}"#.to_string(),
        };
        send_json(&mut stream, &body);
        return;
    }

    if let Some(ip_str) = url.strip_prefix("/lookup/") {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                send_json(&mut stream, r#"{"error":"invalid IP"}"#);
                return;
            }
        };

        let guard = state.read().unwrap();
        let bl = match guard.as_ref() {
            Some(bl) => bl.clone(),
            None => {
                send_json(&mut stream, r#"{"error":"not loaded"}"#);
                return;
            }
        };
        drop(guard);

        send_json(&mut stream, &lookup(&bl, ip).to_json());
        return;
    }

    send_json(&mut stream, r#"{"error":"not found"}"#);
}

fn main() {
    let state: State = Arc::new(RwLock::new(None));

    if let Some(data) = download() {
        *state.write().unwrap() = Some(Arc::new(parse(&data)));
    } else {
        eprintln!("initial download failed");
    }

    let bg = state.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(86400));
            if let Some(data) = download() {
                *bg.write().unwrap() = Some(Arc::new(parse(&data)));
            }
        }
    });

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).unwrap();
    eprintln!("listening on :{port}");

    for stream in listener.incoming().flatten() {
        let state = state.clone();
        thread::spawn(move || handle(stream, &state));
    }
}
