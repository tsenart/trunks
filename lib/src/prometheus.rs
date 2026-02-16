use std::collections::HashMap;

use crate::Hit;

const HISTOGRAM_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct LabelKey {
    method: String,
    url: String,
    status: String,
}

struct PerLabelMetrics {
    latency_sum_ns: u64,
    latency_count: u64,
    latency_buckets: Vec<u64>,
    bytes_in: u64,
    bytes_out: u64,
    fail_counts: HashMap<String, u64>,
}

/// Prometheus metrics collector for HTTP load test results.
///
/// Collects per-label (method, URL, status) histogram and counter metrics
/// and renders them in Prometheus exposition format.
#[derive(Default)]
pub struct PrometheusMetrics {
    per_label: HashMap<LabelKey, PerLabelMetrics>,
}

impl PrometheusMetrics {
    /// Create a new empty metrics collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a hit's metrics.
    pub fn update(&mut self, hit: &Hit) {
        let key = LabelKey {
            method: hit.method.clone(),
            url: hit.url.clone(),
            status: hit.code.to_string(),
        };
        let m = self
            .per_label
            .entry(key)
            .or_insert_with(|| PerLabelMetrics {
                latency_sum_ns: 0,
                latency_count: 0,
                latency_buckets: vec![0; HISTOGRAM_BUCKETS.len()],
                bytes_in: 0,
                bytes_out: 0,
                fail_counts: HashMap::new(),
            });
        let latency_ns = hit.latency.as_nanos() as u64;
        m.latency_sum_ns += latency_ns;
        m.latency_count += 1;
        let latency_s = latency_ns as f64 / 1_000_000_000.0;
        for (i, &bound) in HISTOGRAM_BUCKETS.iter().enumerate() {
            if latency_s <= bound {
                m.latency_buckets[i] += 1;
            }
        }
        m.bytes_in += hit.bytes_in;
        m.bytes_out += hit.bytes_out;
        if !hit.error.is_empty() {
            *m.fail_counts.entry(hit.error.clone()).or_insert(0) += 1;
        }
    }

    /// Render all collected metrics in Prometheus exposition format.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let mut keys: Vec<_> = self.per_label.keys().collect();
        keys.sort_by(|a, b| (&a.method, &a.url, &a.status).cmp(&(&b.method, &b.url, &b.status)));

        s.push_str("# HELP request_seconds Request latency\n");
        s.push_str("# TYPE request_seconds histogram\n");
        for key in &keys {
            let m = &self.per_label[key];
            let labels = format!(
                "method=\"{}\",url=\"{}\",status=\"{}\"",
                key.method, key.url, key.status
            );
            let mut cumulative: u64 = 0;
            for (i, &bound) in HISTOGRAM_BUCKETS.iter().enumerate() {
                cumulative += m.latency_buckets[i];
                s.push_str(&format!(
                    "request_seconds_bucket{{{},le=\"{}\"}} {}\n",
                    labels, bound, cumulative
                ));
            }
            s.push_str(&format!(
                "request_seconds_bucket{{{},le=\"+Inf\"}} {}\n",
                labels, m.latency_count
            ));
            s.push_str(&format!(
                "request_seconds_sum{{{}}} {:.6}\n",
                labels,
                m.latency_sum_ns as f64 / 1_000_000_000.0
            ));
            s.push_str(&format!(
                "request_seconds_count{{{}}} {}\n",
                labels, m.latency_count
            ));
        }

        s.push_str(
            "\n# HELP request_bytes_in Bytes received from servers as response to requests\n",
        );
        s.push_str("# TYPE request_bytes_in counter\n");
        for key in &keys {
            let m = &self.per_label[key];
            let labels = format!(
                "method=\"{}\",url=\"{}\",status=\"{}\"",
                key.method, key.url, key.status
            );
            s.push_str(&format!("request_bytes_in{{{}}} {}\n", labels, m.bytes_in));
        }

        s.push_str("\n# HELP request_bytes_out Bytes sent to servers during requests\n");
        s.push_str("# TYPE request_bytes_out counter\n");
        for key in &keys {
            let m = &self.per_label[key];
            let labels = format!(
                "method=\"{}\",url=\"{}\",status=\"{}\"",
                key.method, key.url, key.status
            );
            s.push_str(&format!(
                "request_bytes_out{{{}}} {}\n",
                labels, m.bytes_out
            ));
        }

        s.push_str("\n# HELP request_fail_count Count of failed requests\n");
        s.push_str("# TYPE request_fail_count counter\n");
        for key in &keys {
            let m = &self.per_label[key];
            let mut errs: Vec<_> = m.fail_counts.iter().collect();
            errs.sort_by_key(|(msg, _)| (*msg).clone());
            for (msg, count) in errs {
                let labels = format!(
                    "method=\"{}\",url=\"{}\",status=\"{}\",message=\"{}\"",
                    key.method,
                    key.url,
                    key.status,
                    msg.replace('"', "\\\"")
                );
                s.push_str(&format!("request_fail_count{{{}}} {}\n", labels, count));
            }
        }

        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_hit(
        method: &str,
        url: &str,
        code: u16,
        latency_ms: u64,
        bytes_in: u64,
        bytes_out: u64,
        error: &str,
    ) -> Hit {
        Hit {
            attack: "test".to_string(),
            seq: 0,
            code,
            timestamp: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1700000000),
            latency: std::time::Duration::from_millis(latency_ms),
            bytes_out,
            bytes_in,
            error: error.to_string(),
            body: vec![],
            method: method.to_string(),
            url: url.to_string(),
            headers: HashMap::new(),
        }
    }

    #[test]
    fn empty_metrics_render() {
        let pm = PrometheusMetrics::new();
        let out = pm.render();
        assert!(out.contains("# HELP request_seconds"));
        assert!(out.contains("# TYPE request_seconds histogram"));
        // No data lines with actual label values
        assert!(!out.contains("method="));
    }

    #[test]
    fn single_hit_render() {
        let mut pm = PrometheusMetrics::new();
        pm.update(&make_hit("GET", "http://localhost/", 200, 50, 1024, 64, ""));
        let out = pm.render();
        assert!(out.contains(
            r#"request_seconds_bucket{method="GET",url="http://localhost/",status="200",le="0.05"} 1"#
        ));
        assert!(out.contains(
            r#"request_seconds_count{method="GET",url="http://localhost/",status="200"} 1"#
        ));
        assert!(out.contains(
            r#"request_bytes_in{method="GET",url="http://localhost/",status="200"} 1024"#
        ));
        assert!(out.contains(
            r#"request_bytes_out{method="GET",url="http://localhost/",status="200"} 64"#
        ));
    }

    #[test]
    fn histogram_bucket_counting() {
        let mut pm = PrometheusMetrics::new();
        pm.update(&make_hit("GET", "http://x/", 200, 500, 0, 0, ""));
        let out = pm.render();
        // 500ms = 0.5s, le="0.5" should include it
        assert!(out.contains(r#"le="0.5"} 1"#));
        // le="0.1" should not include it
        assert!(out.contains(r#"le="0.1"} 0"#));
    }

    #[test]
    fn fail_count_render() {
        let mut pm = PrometheusMetrics::new();
        pm.update(&make_hit("GET", "http://x/", 0, 100, 0, 0, "timeout"));
        let out = pm.render();
        assert!(out.contains("request_fail_count{"));
        assert!(out.contains(r#"message="timeout""#));
    }

    #[test]
    fn multiple_labels() {
        let mut pm = PrometheusMetrics::new();
        pm.update(&make_hit("GET", "http://a/", 200, 10, 0, 0, ""));
        pm.update(&make_hit("POST", "http://b/", 201, 20, 0, 0, ""));
        let out = pm.render();
        assert!(out.contains(r#"method="GET""#));
        assert!(out.contains(r#"method="POST""#));
        assert!(out.contains(r#"url="http://a/""#));
        assert!(out.contains(r#"url="http://b/""#));
    }

    #[test]
    fn cumulative_buckets() {
        let mut pm = PrometheusMetrics::new();
        pm.update(&make_hit("GET", "http://x/", 200, 10, 0, 0, ""));
        pm.update(&make_hit("GET", "http://x/", 200, 100, 0, 0, ""));
        let out = pm.render();
        // Both hits satisfy le="0.1", each increments that bucket directly.
        // The render phase then accumulates, so le="0.01" sees only the 10ms hit's
        // contribution, while le="0.1" sees both.
        assert!(out.contains(r#"le="0.01"} 1"#));
        // le="+Inf" must equal total count
        assert!(out.contains(r#"le="+Inf"} 2"#));
        assert!(out.contains(r#"request_seconds_count"#));
    }
}
