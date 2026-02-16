use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use tdigest::TDigest;

use crate::hit::duration_as_nanos;
use crate::Hit;

#[derive(Debug, Serialize)]
pub struct Metrics {
    pub latencies: LatencyMetrics,
    pub bytes_in: ByteMetrics,
    pub bytes_out: ByteMetrics,
    #[serde(with = "humantime_serde")]
    pub earliest: SystemTime,
    #[serde(with = "humantime_serde")]
    pub latest: SystemTime,
    #[serde(with = "humantime_serde")]
    pub end: SystemTime,
    #[serde(with = "duration_as_nanos")]
    pub duration: Duration,
    #[serde(with = "duration_as_nanos")]
    pub wait: Duration,
    pub requests: u64,
    pub rate: f64,
    pub throughput: f64,
    pub success: f64,
    pub status_codes: BTreeMap<String, u64>,
    pub errors: Vec<String>,
    #[serde(skip)]
    errors_set: HashSet<String>,
    #[serde(skip)]
    success_count: u64,
}

#[derive(Debug, Serialize)]
pub struct LatencyMetrics {
    #[serde(with = "duration_as_nanos")]
    pub total: Duration,
    #[serde(with = "duration_as_nanos")]
    pub mean: Duration,
    #[serde(rename = "50th", with = "duration_as_nanos")]
    pub p50: Duration,
    #[serde(rename = "90th", with = "duration_as_nanos")]
    pub p90: Duration,
    #[serde(rename = "95th", with = "duration_as_nanos")]
    pub p95: Duration,
    #[serde(rename = "99th", with = "duration_as_nanos")]
    pub p99: Duration,
    #[serde(with = "duration_as_nanos")]
    pub max: Duration,
    #[serde(with = "duration_as_nanos")]
    pub min: Duration,
    #[serde(skip)]
    latencies: Vec<f64>,
    #[serde(skip)]
    estimator: Option<TDigest>,
}

impl LatencyMetrics {
    pub fn quantile(&self, q: f64) -> Duration {
        match &self.estimator {
            Some(td) => Duration::from_nanos(td.estimate_quantile(q) as u64),
            None => Duration::ZERO,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct ByteMetrics {
    pub total: u64,
    pub mean: f64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            latencies: LatencyMetrics {
                total: Duration::ZERO,
                mean: Duration::ZERO,
                p50: Duration::ZERO,
                p90: Duration::ZERO,
                p95: Duration::ZERO,
                p99: Duration::ZERO,
                max: Duration::ZERO,
                min: Duration::MAX,
                latencies: Vec::new(),
                estimator: None,
            },
            bytes_in: ByteMetrics::default(),
            bytes_out: ByteMetrics::default(),
            earliest: SystemTime::UNIX_EPOCH,
            latest: SystemTime::UNIX_EPOCH,
            end: SystemTime::UNIX_EPOCH,
            duration: Duration::ZERO,
            wait: Duration::ZERO,
            requests: 0,
            rate: 0.0,
            throughput: 0.0,
            success: 0.0,
            status_codes: BTreeMap::new(),
            errors: Vec::new(),
            errors_set: HashSet::new(),
            success_count: 0,
        }
    }

    pub fn add(&mut self, hit: &Hit) {
        self.requests += 1;

        // Track earliest and latest timestamps.
        if self.earliest == SystemTime::UNIX_EPOCH || hit.timestamp < self.earliest {
            self.earliest = hit.timestamp;
        }
        if hit.timestamp > self.latest {
            self.latest = hit.timestamp;
        }

        // Track end = max(timestamp + latency).
        let hit_end = hit.end();
        if hit_end > self.end {
            self.end = hit_end;
        }

        // Latency tracking.
        let lat = hit.latency;
        self.latencies.total += lat;
        if lat > self.latencies.max {
            self.latencies.max = lat;
        }
        if lat < self.latencies.min {
            self.latencies.min = lat;
        }
        self.latencies.latencies.push(lat.as_nanos() as f64);

        // Bytes.
        self.bytes_in.total += hit.bytes_in;
        self.bytes_out.total += hit.bytes_out;

        // Status codes.
        let code_str = hit.code.to_string();
        *self.status_codes.entry(code_str).or_insert(0) += 1;

        // Success = status in [200, 400).
        if (200..400).contains(&hit.code) {
            self.success_count += 1;
        }

        // Errors (deduplicated).
        if !hit.error.is_empty() && self.errors_set.insert(hit.error.clone()) {
            self.errors.push(hit.error.clone());
        }
    }

    pub fn close(&mut self) {
        if self.requests == 0 {
            return;
        }

        // Fix min if no hits were added (shouldn't happen given the guard above).
        if self.latencies.min == Duration::MAX {
            self.latencies.min = Duration::ZERO;
        }

        // Mean latency.
        self.latencies.mean = self.latencies.total / self.requests as u32;

        // Build t-digest and compute quantiles.
        let td = TDigest::new_with_size(100);
        let td = td.merge_unsorted(std::mem::take(&mut self.latencies.latencies));
        self.latencies.p50 = Duration::from_nanos(td.estimate_quantile(0.50) as u64);
        self.latencies.p90 = Duration::from_nanos(td.estimate_quantile(0.90) as u64);
        self.latencies.p95 = Duration::from_nanos(td.estimate_quantile(0.95) as u64);
        self.latencies.p99 = Duration::from_nanos(td.estimate_quantile(0.99) as u64);
        self.latencies.estimator = Some(td);

        // Byte means.
        self.bytes_in.mean = self.bytes_in.total as f64 / self.requests as f64;
        self.bytes_out.mean = self.bytes_out.total as f64 / self.requests as f64;

        // Duration = latest - earliest.
        self.duration = self
            .latest
            .duration_since(self.earliest)
            .unwrap_or(Duration::ZERO);

        // Wait = end - latest.
        self.wait = self
            .end
            .duration_since(self.latest)
            .unwrap_or(Duration::ZERO);

        // Rate = requests / duration.
        let dur_secs = self.duration.as_secs_f64();
        if dur_secs > 0.0 {
            self.rate = self.requests as f64 / dur_secs;
        }

        // Throughput = success_count / (duration + wait).
        let total_secs = (self.duration + self.wait).as_secs_f64();
        if total_secs > 0.0 {
            self.throughput = self.success_count as f64 / total_secs;
        }

        // Success ratio.
        self.success = self.success_count as f64 / self.requests as f64;
    }
}
