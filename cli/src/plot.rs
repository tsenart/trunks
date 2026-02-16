use clap::Args;
use eyre::Result;
use std::collections::BTreeMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use trunks::{Codec, CsvCodec, Hit, JsonCodec, MsgpackCodec};

use crate::attack::{Input, Output};

#[derive(Args, Debug)]
pub struct Opts {
    /// Plot title
    #[clap(long, default_value = "Vegeta Plot")]
    title: String,

    /// Output file [default: stdout]
    #[clap(long, default_value = "stdout")]
    output: String,

    /// Maximum number of points per series (LTTB downsampling threshold)
    #[clap(long, default_value_t = 4000)]
    threshold: usize,

    /// Input files [default: stdin]
    pub files: Vec<String>,
}

pub async fn plot(opts: &Opts) -> Result<()> {
    let sources: Vec<String> = if opts.files.is_empty() {
        vec!["stdin".to_string()]
    } else {
        opts.files.clone()
    };

    let mut hits: Vec<Hit> = Vec::new();
    for source in &sources {
        let mut input = Input::from_filename(source).await?;
        let buf = input.fill_buf().await?;
        if buf.is_empty() {
            continue;
        }
        let first = buf[0];
        let input_format = if first == b'{' {
            "json"
        } else if first.is_ascii_graphic() {
            "csv"
        } else {
            "msgpack"
        };
        loop {
            let result = match input_format {
                "json" => JsonCodec.decode(&mut input).await,
                "csv" => CsvCodec.decode(&mut input).await,
                _ => MsgpackCodec.decode(&mut input).await,
            };
            match result {
                Ok(hit) => hits.push(hit),
                Err(_) => break,
            }
        }
    }

    if hits.is_empty() {
        eyre::bail!("no data to plot");
    }

    // Per-attack earliest timestamp for relative time.
    let mut attack_origins: BTreeMap<String, std::time::SystemTime> = BTreeMap::new();
    for hit in &hits {
        let entry = attack_origins
            .entry(hit.attack.clone())
            .or_insert(hit.timestamp);
        if hit.timestamp < *entry {
            *entry = hit.timestamp;
        }
    }

    // Build per-series (attack:status) sorted point arrays.
    let mut series_map: BTreeMap<String, Vec<(f64, f64)>> = BTreeMap::new();
    for hit in &hits {
        let label = if hit.error.is_empty() {
            format!("{}: OK", hit.attack)
        } else {
            format!("{}: ERROR", hit.attack)
        };
        let origin = attack_origins[&hit.attack];
        let elapsed = hit
            .timestamp
            .duration_since(origin)
            .unwrap_or_default()
            .as_secs_f64();
        let latency_ms = hit.latency.as_secs_f64() * 1000.0;
        series_map
            .entry(label)
            .or_default()
            .push((elapsed, latency_ms));
    }

    // Sort each series by x and apply LTTB downsampling.
    for points in series_map.values_mut() {
        points.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        if points.len() > opts.threshold {
            *points = lttb(points, opts.threshold);
        }
    }

    let labels: Vec<String> = series_map.keys().cloned().collect();

    // Build per-series JSON arrays: [[x,y], [x,y], ...]
    let mut series_json_parts: Vec<String> = Vec::new();
    for label in &labels {
        let points = &series_map[label];
        let pairs: Vec<String> = points
            .iter()
            .map(|(x, y)| format!("[{:.6},{:.4}]", x, y))
            .collect();
        series_json_parts.push(format!("[{}]", pairs.join(",")));
    }
    let series_json = format!("[{}]", series_json_parts.join(","));

    let success_colors = [
        "#E9D758", "#297373", "#39393A", "#A1CDF4", "#593C8F", "#171738", "#A1674A",
    ];
    let error_colors = [
        "#EE7860", "#DD624E", "#CA4E3E", "#B63A30", "#9F2823", "#881618", "#6F050E",
    ];
    let mut colors = Vec::new();
    let mut si = 0;
    let mut ei = 0;
    for label in &labels {
        if label.contains("ERROR") {
            colors.push(error_colors[ei % error_colors.len()]);
            ei += 1;
        } else {
            colors.push(success_colors[si % success_colors.len()]);
            si += 1;
        }
    }

    let labels_json: Vec<String> = labels
        .iter()
        .map(|l| format!("\"{}\"", l.replace('"', "\\\"")))
        .collect();
    let colors_json: Vec<String> = colors.iter().map(|c| format!("\"{}\"", c)).collect();

    let opts_json = format!(
        "{{\"title\":\"{}\",\"labels\":[{}],\"colors\":[{}]}}",
        opts.title.replace('"', "\\\""),
        labels_json.join(","),
        colors_json.join(","),
    );

    let html = generate_plot_html(&opts.title, &series_json, &opts_json);

    let mut output = Output::from_filename(&opts.output).await?;
    output.write_all(html.as_bytes()).await?;
    output.flush().await?;

    Ok(())
}

/// Largest Triangle Three Buckets (LTTB) downsampling.
fn lttb(data: &[(f64, f64)], threshold: usize) -> Vec<(f64, f64)> {
    let n = data.len();
    if threshold >= n || threshold < 3 {
        return data.to_vec();
    }

    let mut sampled = Vec::with_capacity(threshold);
    sampled.push(data[0]);

    let bucket_size = (n - 2) as f64 / (threshold - 2) as f64;

    let mut a_idx = 0usize;

    for i in 0..(threshold - 2) {
        let bucket_start = ((i as f64 + 1.0) * bucket_size) as usize + 1;
        let bucket_end = (((i as f64 + 2.0) * bucket_size) as usize + 1).min(n - 1);

        // Average of next bucket for the triangle area calculation.
        let next_start = bucket_end;
        let next_end = (((i as f64 + 3.0) * bucket_size) as usize + 1).min(n);
        let mut avg_x = 0.0f64;
        let mut avg_y = 0.0f64;
        let next_len = next_end - next_start;
        if next_len > 0 {
            for j in next_start..next_end {
                avg_x += data[j].0;
                avg_y += data[j].1;
            }
            avg_x /= next_len as f64;
            avg_y /= next_len as f64;
        }

        let (ax, ay) = data[a_idx];
        let mut max_area = -1.0f64;
        let mut max_idx = bucket_start;

        for j in bucket_start..bucket_end {
            let area = ((data[j].0 - ax) * (avg_y - ay) - (avg_x - ax) * (data[j].1 - ay)).abs();
            if area > max_area {
                max_area = area;
                max_idx = j;
            }
        }

        sampled.push(data[max_idx]);
        a_idx = max_idx;
    }

    sampled.push(data[n - 1]);
    sampled
}

fn generate_plot_html(title: &str, series_data: &str, opts: &str) -> String {
    format!(
        r##"<!doctype html>
<html>
<head>
  <title>{title}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #0f1419; color: #e6edf3; }}
    .container {{ max-width: 1600px; margin: 0 auto; }}
    h1 {{ font-size: 24px; font-weight: 600; margin: 0 0 20px 0; }}
    .chart {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
    canvas {{ width: 100%; }}
    .legend {{ display: flex; gap: 16px; margin-top: 12px; flex-wrap: wrap; font-size: 13px; }}
    .legend-item {{ display: flex; align-items: center; gap: 6px; }}
    .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
    .controls {{ margin-bottom: 16px; display: flex; gap: 8px; }}
    .btn {{ padding: 6px 12px; border-radius: 6px; font-size: 13px; cursor: pointer; border: 1px solid #30363d; background: #161b22; color: #e6edf3; }}
    .btn:hover {{ background: #1f2937; }}
    .btn.active {{ background: #1f6feb; border-color: #1f6feb; color: #fff; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>{title}</h1>
    <div class="controls">
      <button class="btn active" onclick="toggleLog()">Log Scale</button>
    </div>
    <div class="chart">
      <canvas id="chart" height="500"></canvas>
      <div class="legend" id="legend"></div>
    </div>
  </div>
  <script>
    const opts = {opts};
    const seriesData = {series_data};
    let logScale = true;

    function toggleLog() {{
      logScale = !logScale;
      const btn = document.querySelector('.btn');
      btn.classList.toggle('active', logScale);
      draw();
    }}

    function draw() {{
      const canvas = document.getElementById('chart');
      const ctx = canvas.getContext('2d');
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * dpr;
      canvas.height = 500 * dpr;
      ctx.scale(dpr, dpr);
      const W = rect.width;
      const H = 500;
      const pad = {{top: 20, right: 20, bottom: 50, left: 80}};
      const pw = W - pad.left - pad.right;
      const ph = H - pad.top - pad.bottom;

      ctx.clearRect(0, 0, W, H);

      if (seriesData.length === 0) return;

      let xMin = Infinity, xMax = -Infinity;
      let allY = [];
      for (const series of seriesData) {{
        for (const [x, y] of series) {{
          if (x < xMin) xMin = x;
          if (x > xMax) xMax = x;
          if (y > 0) allY.push(y);
        }}
      }}
      if (!allY.length) return;

      let yMin = Math.min(...allY);
      let yMax = Math.max(...allY);
      if (logScale) yMin = Math.max(0.001, yMin);

      function xToP(x) {{ return pad.left + (x - xMin) / (xMax - xMin || 1) * pw; }}
      function yToP(y) {{
        if (logScale) {{
          const logMin = Math.log10(yMin);
          const logMax = Math.log10(yMax);
          return pad.top + ph - (Math.log10(Math.max(y, yMin)) - logMin) / (logMax - logMin || 1) * ph;
        }}
        return pad.top + ph - (y - yMin) / (yMax - yMin || 1) * ph;
      }}

      ctx.strokeStyle = '#30363d';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 5; i++) {{
        const y = pad.top + (ph / 5) * i;
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(W - pad.right, y); ctx.stroke();
      }}

      ctx.fillStyle = '#8b949e';
      ctx.font = '11px monospace';
      ctx.textAlign = 'right';
      for (let i = 0; i <= 5; i++) {{
        const frac = 1 - i / 5;
        let val;
        if (logScale) {{
          val = Math.pow(10, Math.log10(yMin) + frac * (Math.log10(yMax) - Math.log10(yMin)));
        }} else {{
          val = yMin + frac * (yMax - yMin);
        }}
        const y = pad.top + (ph / 5) * i;
        ctx.fillText(formatDur(val), pad.left - 8, y + 4);
      }}

      ctx.textAlign = 'center';
      for (let i = 0; i <= 5; i++) {{
        const val = xMin + (i / 5) * (xMax - xMin);
        const x = pad.left + (pw / 5) * i;
        ctx.fillText(val.toFixed(1) + 's', x, H - pad.bottom + 20);
      }}

      ctx.fillStyle = '#8b949e';
      ctx.font = '12px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Seconds elapsed', pad.left + pw / 2, H - 8);
      ctx.save();
      ctx.translate(16, pad.top + ph / 2);
      ctx.rotate(-Math.PI / 2);
      ctx.fillText('Latency', 0, 0);
      ctx.restore();

      for (let s = 0; s < seriesData.length; s++) {{
        const color = opts.colors[s] || '#8b949e';
        ctx.fillStyle = color;
        for (const [x, y] of seriesData[s]) {{
          ctx.fillRect(xToP(x) - 0.5, yToP(y) - 0.5, 1.5, 1.5);
        }}
      }}

      const legend = document.getElementById('legend');
      legend.innerHTML = '';
      for (let s = 0; s < opts.labels.length; s++) {{
        const div = document.createElement('div');
        div.className = 'legend-item';
        div.innerHTML = `<span class="legend-dot" style="background:${{opts.colors[s]}}"></span>${{opts.labels[s]}}`;
        legend.appendChild(div);
      }}
    }}

    function formatDur(ms) {{
      if (ms >= 1000) return (ms / 1000).toFixed(2) + 's';
      if (ms >= 1) return ms.toFixed(2) + 'ms';
      return (ms * 1000).toFixed(0) + 'µs';
    }}

    draw();
    window.addEventListener('resize', draw);
  </script>
</body>
</html>"##
    )
}
