use std::io::Write;
use std::time::Duration;

use tabwriter::TabWriter;

use crate::{Hit, Metrics};

/// Round a duration to the next most precise unit, matching vegeta's rounding.
fn round(d: Duration) -> Duration {
    const HOUR: Duration = Duration::from_secs(3600);
    const MINUTE: Duration = Duration::from_secs(60);
    const SECOND: Duration = Duration::from_secs(1);
    const MILLI: Duration = Duration::from_millis(1);
    const MICRO: Duration = Duration::from_micros(1);

    let nanos = d.as_nanos();

    if d >= HOUR {
        // Round to minutes.
        let unit = MINUTE.as_nanos();
        let rounded = ((nanos + unit / 2) / unit) * unit;
        Duration::from_nanos(rounded as u64)
    } else if d >= MINUTE {
        // Round to seconds.
        let unit = SECOND.as_nanos();
        let rounded = ((nanos + unit / 2) / unit) * unit;
        Duration::from_nanos(rounded as u64)
    } else if d >= SECOND {
        // Round to milliseconds.
        let unit = MILLI.as_nanos();
        let rounded = ((nanos + unit / 2) / unit) * unit;
        Duration::from_nanos(rounded as u64)
    } else if d >= MILLI {
        // Round to microseconds.
        let unit = MICRO.as_nanos();
        let rounded = ((nanos + unit / 2) / unit) * unit;
        Duration::from_nanos(rounded as u64)
    } else if d >= MICRO {
        // Round to nanoseconds (already at ns precision).
        d
    } else {
        d
    }
}

/// Format a duration the way Go's time.Duration.String() does.
fn go_duration_string(d: Duration) -> String {
    let total_nanos = d.as_nanos();
    if total_nanos == 0 {
        return "0s".to_string();
    }

    let mut buf = String::new();
    let mut remaining = total_nanos;

    // Hours
    let h = remaining / 3_600_000_000_000;
    if h > 0 {
        buf.push_str(&format!("{}h", h));
        remaining %= 3_600_000_000_000;
    }

    // Minutes
    let m = remaining / 60_000_000_000;
    if m > 0 {
        buf.push_str(&format!("{}m", m));
        remaining %= 60_000_000_000;
    }

    // Now remaining < 60s, express as fractional seconds/ms/us/ns.
    if remaining == 0 {
        return buf;
    }

    if remaining >= 1_000_000_000 {
        let sec = remaining / 1_000_000_000;
        let frac = remaining % 1_000_000_000;
        if frac == 0 {
            buf.push_str(&format!("{}s", sec));
        } else {
            let frac_str = format!("{:09}", frac);
            let frac_str = frac_str.trim_end_matches('0');
            buf.push_str(&format!("{}.{}s", sec, frac_str));
        }
    } else if remaining >= 1_000_000 {
        let ms = remaining / 1_000_000;
        let frac = remaining % 1_000_000;
        if frac == 0 {
            buf.push_str(&format!("{}ms", ms));
        } else {
            let frac_str = format!("{:06}", frac);
            let frac_str = frac_str.trim_end_matches('0');
            buf.push_str(&format!("{}.{}ms", ms, frac_str));
        }
    } else if remaining >= 1_000 {
        let us = remaining / 1_000;
        let frac = remaining % 1_000;
        if frac == 0 {
            buf.push_str(&format!("{}µs", us));
        } else {
            let frac_str = format!("{:03}", frac);
            let frac_str = frac_str.trim_end_matches('0');
            buf.push_str(&format!("{}.{}µs", us, frac_str));
        }
    } else {
        buf.push_str(&format!("{}ns", remaining));
    }

    buf
}

pub fn report_text(m: &Metrics, w: &mut dyn Write) -> eyre::Result<()> {
    let mut tw = TabWriter::new(w);

    write!(
        tw,
        "Requests\t[total, rate, throughput]\t{}, {:.2}, {:.2}\n\
         Duration\t[total, attack, wait]\t{}, {}, {}\n\
         Latencies\t[min, mean, 50, 90, 95, 99, max]\t{}, {}, {}, {}, {}, {}, {}\n\
         Bytes In\t[total, mean]\t{}, {:.2}\n\
         Bytes Out\t[total, mean]\t{}, {:.2}\n\
         Success\t[ratio]\t{:.2}%\n\
         Status Codes\t[code:count]\t",
        m.requests,
        m.rate,
        m.throughput,
        go_duration_string(round(m.duration + m.wait)),
        go_duration_string(round(m.duration)),
        go_duration_string(round(m.wait)),
        go_duration_string(round(m.latencies.min)),
        go_duration_string(round(m.latencies.mean)),
        go_duration_string(round(m.latencies.p50)),
        go_duration_string(round(m.latencies.p90)),
        go_duration_string(round(m.latencies.p95)),
        go_duration_string(round(m.latencies.p99)),
        go_duration_string(round(m.latencies.max)),
        m.bytes_in.total,
        m.bytes_in.mean,
        m.bytes_out.total,
        m.bytes_out.mean,
        m.success * 100.0,
    )?;

    let mut codes: Vec<_> = m.status_codes.keys().collect();
    codes.sort();
    for code in codes {
        let count = m.status_codes[code];
        write!(tw, "{}:{}  ", code, count)?;
    }

    writeln!(tw, "\nError Set:")?;
    for e in &m.errors {
        writeln!(tw, "{}", e)?;
    }

    tw.flush()?;
    Ok(())
}

pub fn report_json(m: &Metrics, w: &mut dyn Write) -> eyre::Result<()> {
    serde_json::to_writer(&mut *w, m)?;
    w.write_all(b"\n")?;
    Ok(())
}

/// A bucketed latency histogram.
pub struct Histogram {
    pub buckets: Vec<Duration>,
    pub counts: Vec<u64>,
    pub total: u64,
}

impl Histogram {
    /// Create a new histogram with the given bucket boundaries.
    pub fn new(buckets: Vec<Duration>) -> Self {
        let counts = vec![0u64; buckets.len()];
        Histogram {
            buckets,
            counts,
            total: 0,
        }
    }

    /// Parse bucket boundaries from a string like "[0,1ms,10ms,100ms]".
    pub fn from_bucket_str(s: &str) -> eyre::Result<Self> {
        let s = s.trim();
        if s.len() < 2 || !s.starts_with('[') || !s.ends_with(']') {
            return Err(eyre::eyre!("bad buckets: {}", s));
        }
        let inner = &s[1..s.len() - 1];
        let mut buckets = Vec::new();
        for (i, part) in inner.split(',').enumerate() {
            let part = part.trim();
            let d = parse_go_duration(part)?;
            if i == 0 && d > Duration::ZERO {
                buckets.push(Duration::ZERO);
            }
            buckets.push(d);
        }
        if buckets.is_empty() {
            return Err(eyre::eyre!("bad buckets: {}", s));
        }
        Ok(Histogram::new(buckets))
    }

    /// Add a hit's latency to the appropriate bucket.
    pub fn add(&mut self, hit: &Hit) {
        if self.counts.len() != self.buckets.len() {
            self.counts = vec![0u64; self.buckets.len()];
        }

        let mut i = 0;
        while i < self.buckets.len() - 1 {
            if hit.latency >= self.buckets[i] && hit.latency < self.buckets[i + 1] {
                break;
            }
            i += 1;
        }

        self.total += 1;
        self.counts[i] += 1;
    }

    /// Return the nth bucket's (left, right) boundary as strings.
    fn nth(&self, i: usize) -> (String, String) {
        if i >= self.buckets.len() - 1 {
            (go_duration_string(self.buckets[i]), "+Inf".to_string())
        } else {
            (
                go_duration_string(self.buckets[i]),
                go_duration_string(self.buckets[i + 1]),
            )
        }
    }
}

fn parse_go_duration(s: &str) -> eyre::Result<Duration> {
    let s = s.trim();
    if s == "0" || s == "0s" {
        return Ok(Duration::ZERO);
    }
    humantime_serde::re::humantime::parse_duration(s)
        .map_err(|e| eyre::eyre!("bad duration '{}': {}", s, e))
}

pub fn report_histogram(h: &Histogram, w: &mut dyn Write) -> eyre::Result<()> {
    let mut tw = TabWriter::new(w);
    writeln!(tw, "Bucket\t\t#\t%\tHistogram")?;

    for (i, &count) in h.counts.iter().enumerate() {
        let ratio = if h.total > 0 {
            count as f64 / h.total as f64
        } else {
            0.0
        };
        let (lo, hi) = h.nth(i);
        let pad = "#".repeat((ratio * 75.0) as usize);
        writeln!(
            tw,
            "[{},\t{}]\t{}\t{:.2}%\t{}",
            lo,
            hi,
            count,
            ratio * 100.0,
            pad
        )?;
    }

    tw.flush()?;
    Ok(())
}

const LOGARITHMIC: &[f64] = &[
    0.00, 0.100, 0.200, 0.300, 0.400, 0.500, 0.550, 0.600, 0.650, 0.700, 0.750, 0.775, 0.800,
    0.825, 0.850, 0.875, 0.8875, 0.900, 0.9125, 0.925, 0.9375, 0.94375, 0.950, 0.95625, 0.9625,
    0.96875, 0.971875, 0.975, 0.978125, 0.98125, 0.984375, 0.985938, 0.9875, 0.989062, 0.990625,
    0.992188, 0.992969, 0.99375, 0.994531, 0.995313, 0.996094, 0.996484, 0.996875, 0.997266,
    0.997656, 0.998047, 0.998242, 0.998437, 0.998633, 0.998828, 0.999023, 0.999121, 0.999219,
    0.999316, 0.999414, 0.999512, 0.999561, 0.999609, 0.999658, 0.999707, 0.999756, 0.99978,
    0.999805, 0.999829, 0.999854, 0.999878, 0.99989, 0.999902, 0.999915, 0.999927, 0.999939,
    0.999945, 0.999951, 0.999957, 0.999963, 0.999969, 0.999973, 0.999976, 0.999979, 0.999982,
    0.999985, 0.999986, 0.999988, 0.999989, 0.999991, 0.999992, 0.999993, 0.999994, 0.999995,
    0.999996, 0.999997, 0.999998, 0.999999, 1.0,
];

/// Convert a Duration to fractional milliseconds, matching vegeta's milliseconds().
fn milliseconds(d: Duration) -> f64 {
    let ms = d.as_millis() as f64;
    let ns = (d.as_nanos() % 1_000_000) as f64;
    ms + ns / 1e6
}

fn one_by_quantile(q: f64) -> f64 {
    if q < 1.0 {
        1.0 / (1.0 - q)
    } else {
        10_000_000.0
    }
}

pub fn report_hdrplot(m: &Metrics, w: &mut dyn Write) -> eyre::Result<()> {
    let mut tw = TabWriter::new(w);
    writeln!(tw, "Value(ms)\tPercentile\tTotalCount\t1/(1-Percentile)")?;

    let total = m.requests as f64;
    for &q in LOGARITHMIC {
        let value = milliseconds(m.latencies.quantile(q));
        let one_by = one_by_quantile(q);
        let count = ((q * total) + 0.5) as i64;
        writeln!(tw, "{:.6}\t{:.6}\t{}\t{:.6}", value, q, count, one_by)?;
    }

    tw.flush()?;
    Ok(())
}
