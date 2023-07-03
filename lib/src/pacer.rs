use std::fmt;
use std::time::Duration;

// A Pacer defines the rate of hits during an Attack.
pub trait Pacer: Send + Sync {
    // Pace returns the duration an Attacker should wait until
    // hitting the next Target, given an already elapsed duration and
    // completed hits. If the second return value is true, an attacker
    // should stop sending hits.
    fn pace(&self, elapsed: Duration, hits: u64) -> (Duration, bool);
}

#[derive(Debug, Clone)]
pub struct ConstantPacer {
    pub freq: u64,
    pub per: Duration,
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
        if std::u64::MAX / interval < hits {
            // We would overflow delta if we continued, so stop the attack.
            return (Duration::ZERO, true);
        }

        let delta = Duration::from_nanos((hits + 1) * interval);
        if delta > elapsed {
            return (delta - elapsed, false);
        }

        (Duration::ZERO, false)
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
