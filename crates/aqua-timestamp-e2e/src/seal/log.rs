//! The per-step log of a seal run: assertion lines and one final PASS or FAIL per step.

use std::path::Path;

use anyhow::{Context, Result};

/// One step's log. Every line also goes to stdout. A failed assertion names the falsifier it
/// fires; the step's verdict lists those, each once.
pub struct StepLog {
    n: u8,
    lines: Vec<String>,
    fails: Vec<String>,
}

impl StepLog {
    pub fn new(n: u8, title: &str, header: &[String]) -> Self {
        let mut lines = vec![format!("# seal e2e step {n}: {title}")];
        lines.extend(header.iter().cloned());
        lines.push(format!("# step started {}", utc()));
        Self {
            n,
            lines,
            fails: Vec::new(),
        }
    }

    pub fn l(&mut self, s: impl Into<String>) {
        let s = s.into();
        println!("[step {}] {}", self.n, s.lines().next().unwrap_or(""));
        self.lines.push(s);
    }

    /// One assertion line. Returns `ok`, so a caller can stop on a failure.
    pub fn check(&mut self, ok: bool, what: impl AsRef<str>, falsifier: &str) -> bool {
        self.l(format!(
            "ASSERT {} {}",
            if ok { "ok  " } else { "FAIL" },
            what.as_ref()
        ));
        if !ok && !self.fails.iter().any(|f| f == falsifier) {
            self.fails.push(falsifier.to_string());
        }
        ok
    }

    pub fn passed(&self) -> bool {
        self.fails.is_empty()
    }

    pub fn number(&self) -> u8 {
        self.n
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn verdict(&self) -> String {
        if self.fails.is_empty() {
            format!("STEP {} PASS", self.n)
        } else {
            format!("STEP {} FAIL {}", self.n, self.fails.join("; "))
        }
    }

    /// Write `step-<n>.log` under `dir`: the lines, one closing line, the verdict.
    pub fn write(&self, dir: &Path, closing: &str) -> Result<()> {
        let mut text = self.lines.join("\n");
        text.push_str(&format!("\n# {closing}\n"));
        text.push_str(&self.verdict());
        text.push('\n');
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let path = dir.join(format!("step-{}.log", self.n));
        std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))
    }
}

/// True when every step passed and at least one ran.
pub fn all_passed(logs: &[StepLog]) -> bool {
    !logs.is_empty() && logs.iter().all(StepLog::passed)
}

pub fn utc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_assertion_fails_the_step_and_names_the_falsifier_once() {
        let mut log = StepLog::new(3, "t", &[]);
        let fine = !"".contains('x');
        assert!(log.check(fine, "fine", "x"));
        assert!(log.passed());
        assert_eq!(log.verdict(), "STEP 3 PASS");
        assert!(!log.check(false, "bad", "stub"));
        assert!(!log.check(false, "bad again", "stub"));
        assert_eq!(log.verdict(), "STEP 3 FAIL stub");
    }

    #[test]
    fn no_step_run_is_no_pass() {
        assert!(!all_passed(&[]));
    }
}
