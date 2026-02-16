use std::f64::consts::PI;
use std::fmt;
use std::time::Duration;

// SinePacer offset constants.
pub const MEAN_UP: f64 = 0.0;
pub const PEAK: f64 = std::f64::consts::FRAC_PI_2;
pub const MEAN_DOWN: f64 = PI;
pub const TROUGH: f64 = 3.0 * std::f64::consts::FRAC_PI_2;

// A Pacer defines the rate of hits during an Attack.
pub trait Pacer: Send + Sync {
    // Pace returns the duration an Attacker should wait until
    // hitting the next Target, given an already elapsed duration and
    // completed hits. If the second return value is true, an attacker
    // should stop sending hits.
    fn pace(&self, elapsed: Duration, hits: u64) -> (Duration, bool);

    // Rate returns a Pacer's instantaneous hit rate (per seconds)
    // at the given elapsed duration of an attack.
    fn rate(&self, elapsed: Duration) -> f64;
}

impl Pacer for Box<dyn Pacer> {
    fn pace(&self, elapsed: Duration, hits: u64) -> (Duration, bool) {
        (**self).pace(elapsed, hits)
    }

    fn rate(&self, elapsed: Duration) -> f64 {
        (**self).rate(elapsed)
    }
}

#[derive(Debug, Clone)]
pub struct ConstantPacer {
    pub freq: u64,
    pub per: Duration,
}

impl ConstantPacer {
    fn hits_per_ns(&self) -> f64 {
        self.freq as f64 / self.per.as_nanos() as f64
    }
}

impl Pacer for ConstantPacer {
    fn pace(&self, elapsed: Duration, hits: u64) -> (Duration, bool) {
        if self.per.as_nanos() == 0 || self.freq == 0 {
            return (Duration::ZERO, false);
        }

        let expected_hits = self.freq * (elapsed.as_nanos() / self.per.as_nanos()) as u64;
        if hits < expected_hits {
            // Running behind, send next hit immediately.
            return (Duration::ZERO, false);
        }

        let interval = self.per.as_nanos() as u64 / self.freq;
        if u64::MAX / interval < hits {
            // We would overflow delta if we continued, so stop the attack.
            return (Duration::ZERO, true);
        }

        let delta = Duration::from_nanos((hits + 1) * interval);
        if delta > elapsed {
            return (delta - elapsed, false);
        }

        (Duration::ZERO, false)
    }

    fn rate(&self, _elapsed: Duration) -> f64 {
        self.hits_per_ns() * 1e9
    }
}

impl fmt::Display for ConstantPacer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ConstantPacer{{Freq: {}, Per: {:?}}}",
            self.freq, self.per
        )
    }
}

// LinearPacer paces an attack by starting at a given request rate
// and increasing linearly with the given slope.
#[derive(Debug, Clone)]
pub struct LinearPacer {
    pub start_at: ConstantPacer,
    pub slope: f64,
}

impl LinearPacer {
    fn hits(&self, t: Duration) -> f64 {
        if t.is_zero() {
            return 0.0;
        }

        let a = self.slope;
        let b = self.start_at.hits_per_ns() * 1e9;
        let x = t.as_secs_f64();

        (a * x.powi(2)) / 2.0 + b * x
    }
}

impl Pacer for LinearPacer {
    fn pace(&self, elapsed: Duration, hits: u64) -> (Duration, bool) {
        if self.start_at.per.as_nanos() == 0 || self.start_at.freq == 0 {
            return (Duration::ZERO, false);
        }

        let expected_hits = self.hits(elapsed);
        if hits == 0 || hits < expected_hits as u64 {
            // Running behind, send next hit immediately.
            return (Duration::ZERO, false);
        }

        let rate = self.rate(elapsed);
        let interval = (1e9 / rate).round();

        let n = interval as u64;
        if n != 0 && u64::MAX / n < hits {
            // We would overflow wait if we continued, so stop the attack.
            return (Duration::ZERO, true);
        }

        let delta = (hits + 1) as f64 - expected_hits;
        let wait_ns = interval * delta;
        if !wait_ns.is_finite() || wait_ns < 0.0 {
            return (Duration::ZERO, false);
        }
        let wait = Duration::from_nanos(wait_ns as u64);

        (wait, false)
    }

    fn rate(&self, elapsed: Duration) -> f64 {
        let a = self.slope;
        let x = elapsed.as_secs_f64();
        let b = self.start_at.hits_per_ns() * 1e9;
        a * x + b
    }
}

impl fmt::Display for LinearPacer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Linear{{{} + {}/s}}", self.start_at, self.slope)
    }
}

// SinePacer is a Pacer that describes attack request rates with the equation:
//   R = M + A * sin(O + (2π/P) * t)
#[derive(Debug, Clone)]
pub struct SinePacer {
    pub period: Duration,
    pub mean: ConstantPacer,
    pub amp: ConstantPacer,
    pub start_at: f64,
}

impl SinePacer {
    fn invalid(&self) -> bool {
        self.period.is_zero()
            || self.mean.hits_per_ns() <= 0.0
            || self.amp.hits_per_ns() >= self.mean.hits_per_ns()
    }

    fn amp_hits(&self) -> f64 {
        (self.amp.hits_per_ns() * self.period.as_nanos() as f64) / (2.0 * PI)
    }

    fn radians(&self, t: Duration) -> f64 {
        self.start_at + t.as_nanos() as f64 * 2.0 * PI / self.period.as_nanos() as f64
    }

    fn hits_per_ns(&self, t: Duration) -> f64 {
        self.mean.hits_per_ns() + self.amp.hits_per_ns() * self.radians(t).sin()
    }

    fn hits(&self, t: Duration) -> f64 {
        if t.is_zero() || self.invalid() {
            return 0.0;
        }
        self.mean.hits_per_ns() * t.as_nanos() as f64
            + self.amp_hits() * (self.start_at.cos() - self.radians(t).cos())
    }
}

impl Pacer for SinePacer {
    fn pace(&self, elapsed: Duration, hits: u64) -> (Duration, bool) {
        if self.invalid() {
            return (Duration::ZERO, true);
        }

        let expected_hits = self.hits(elapsed);
        if hits < expected_hits as u64 {
            // Running behind, send next hit immediately.
            return (Duration::ZERO, false);
        }

        // Solve for the duration numerically.
        let hpns = self.hits_per_ns(elapsed);
        if hpns <= 0.0 {
            return (Duration::ZERO, false);
        }
        let ns_per_hit = (1.0 / hpns).round();
        let hits_to_wait = (hits + 1) as f64 - expected_hits;
        let mut next_hit_in = ns_per_hit * hits_to_wait;

        // If we can't converge to an error of <1e-3 within 5 iterations, bail.
        for _ in 0..5 {
            if !next_hit_in.is_finite() || next_hit_in < 0.0 {
                return (Duration::ZERO, false);
            }
            let hits_at_guess = self.hits(elapsed + Duration::from_nanos(next_hit_in as u64));
            let err = (hits + 1) as f64 - hits_at_guess;
            if err.abs() < 1e-3 {
                return (Duration::from_nanos(next_hit_in as u64), false);
            }
            let denom = hits_at_guess - hits as f64;
            if denom.abs() < 1e-9 {
                return (Duration::ZERO, false);
            }
            next_hit_in /= denom;
        }

        if !next_hit_in.is_finite() || next_hit_in < 0.0 {
            return (Duration::ZERO, false);
        }
        (Duration::from_nanos(next_hit_in as u64), false)
    }

    fn rate(&self, elapsed: Duration) -> f64 {
        self.hits_per_ns(elapsed) * 1e9
    }
}

impl fmt::Display for SinePacer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Sine{{{} ± {} / {:?}, offset {}π}}",
            self.mean,
            self.amp,
            self.period,
            self.start_at / PI
        )
    }
}
