/// Largest Triangle Three Buckets (LTTB) downsampling algorithm.
///
/// Reduces a sorted slice of (x, y) data points to at most `threshold` points
/// while preserving the visual shape of the data. Useful for rendering large
/// time-series datasets efficiently.
///
/// Returns the original data unchanged if `threshold >= data.len()` or `threshold < 3`.
pub fn downsample(data: &[(f64, f64)], threshold: usize) -> Vec<(f64, f64)> {
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
            for item in data.iter().take(next_end).skip(next_start) {
                avg_x += item.0;
                avg_y += item.1;
            }
            avg_x /= next_len as f64;
            avg_y /= next_len as f64;
        }

        let (ax, ay) = data[a_idx];
        let mut max_area = -1.0f64;
        let mut max_idx = bucket_start;

        for (j, item) in data.iter().enumerate().take(bucket_end).skip(bucket_start) {
            let area = ((item.0 - ax) * (avg_y - ay) - (avg_x - ax) * (item.1 - ay)).abs();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_ge_n_returns_original() {
        let data: Vec<(f64, f64)> = (0..5).map(|i| (i as f64, i as f64)).collect();
        assert_eq!(downsample(&data, 5), data);
        assert_eq!(downsample(&data, 10), data);
    }

    #[test]
    fn threshold_lt_3_returns_original() {
        let data: Vec<(f64, f64)> = (0..5).map(|i| (i as f64, i as f64)).collect();
        assert_eq!(downsample(&data, 2), data);
        assert_eq!(downsample(&data, 1), data);
    }

    #[test]
    fn preserves_first_and_last() {
        let data: Vec<(f64, f64)> = (0..10).map(|i| (i as f64, i as f64)).collect();
        let result = downsample(&data, 5);
        assert_eq!(result.first(), Some(&(0.0, 0.0)));
        assert_eq!(result.last(), Some(&(9.0, 9.0)));
    }

    #[test]
    fn correct_downsampling_size() {
        let data: Vec<(f64, f64)> = (0..100).map(|i| (i as f64, (i * i) as f64)).collect();
        let result = downsample(&data, 20);
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn single_point() {
        let data = vec![(1.0, 1.0)];
        assert_eq!(downsample(&data, 5), data);
    }

    #[test]
    fn two_points() {
        let data = vec![(0.0, 0.0), (1.0, 1.0)];
        assert_eq!(downsample(&data, 5), data);
    }

    #[test]
    fn three_points_to_three() {
        let data = vec![(0.0, 0.0), (1.0, 1.0), (2.0, 2.0)];
        assert_eq!(downsample(&data, 3), data);
    }

    #[test]
    fn known_downsampling() {
        let data = vec![
            (0.0, 0.0),
            (1.0, 10.0),
            (2.0, 2.0),
            (3.0, 8.0),
            (4.0, 4.0),
            (5.0, 6.0),
            (6.0, 1.0),
            (7.0, 9.0),
            (8.0, 3.0),
            (9.0, 7.0),
        ];
        let result = downsample(&data, 5);
        assert_eq!(result.len(), 5);
        assert_eq!(result[0], (0.0, 0.0));
        assert_eq!(*result.last().unwrap(), (9.0, 7.0));
    }
}
