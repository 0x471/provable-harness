//! In-VM virtual filesystem. File tools run *inside* the proof, so their effects
//! are proven, not attested. Each file carries a `secret` label so taint survives
//! copies: anything written while the session is tainted is itself secret.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::hash::{domain, Digest, Hasher};
use crate::policy::{is_under, validate_file_path};

pub const MAX_FILES: usize = 1024;
pub const MAX_FILE_CHARS: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceFile {
    pub path: String,
    pub content: String,
    pub secret: bool,
}

#[derive(Clone, Debug)]
struct Entry {
    content: String,
    secret: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Workspace {
    files: BTreeMap<String, Entry>,
}

impl Workspace {
    pub fn new(files: &[WorkspaceFile]) -> Result<Self, String> {
        if files.len() > MAX_FILES {
            return Err("too many workspace files".into());
        }
        let mut ws = Workspace::default();
        for f in files {
            validate_file_path(&f.path)?;
            if f.content.len() > MAX_FILE_CHARS {
                return Err(format!("workspace file {} too large", f.path));
            }
            let prev = ws.files.insert(
                f.path.clone(),
                Entry {
                    content: f.content.clone(),
                    secret: f.secret,
                },
            );
            if prev.is_some() {
                return Err(format!("duplicate workspace path {}", f.path));
            }
        }
        Ok(ws)
    }

    /// Commitment to the full state (paths in sorted order, labels, contents).
    pub fn root(&self) -> Digest {
        let mut h = Hasher::new(domain::WORKSPACE);
        h.u64(self.files.len() as u64);
        for (path, e) in &self.files {
            h.str(path).bool(e.secret).str(&e.content);
        }
        h.finish()
    }

    /// `(content, secret_label)`.
    pub fn read(&self, path: &str) -> Option<(&str, bool)> {
        self.files.get(path).map(|e| (e.content.as_str(), e.secret))
    }

    pub fn write(&mut self, path: &str, content: &str, secret: bool) -> Result<(), String> {
        if content.len() > MAX_FILE_CHARS {
            return Err("file too large".into());
        }
        if !self.files.contains_key(path) && self.files.len() >= MAX_FILES {
            return Err("too many files".into());
        }
        self.files.insert(
            path.to_string(),
            Entry {
                content: content.to_string(),
                secret,
            },
        );
        Ok(())
    }

    /// Paths under `dir` (sorted), keeping only those `keep` accepts.
    pub fn list(&self, dir: &str, keep: impl Fn(&str) -> bool) -> Vec<String> {
        self.files
            .keys()
            .filter(|p| is_under(p, dir) && keep(p))
            .cloned()
            .collect()
    }

    pub fn export(&self) -> Vec<WorkspaceFile> {
        self.files
            .iter()
            .map(|(p, e)| WorkspaceFile {
                path: p.clone(),
                content: e.content.clone(),
                secret: e.secret,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(p: &str, c: &str) -> WorkspaceFile {
        WorkspaceFile {
            path: p.into(),
            content: c.into(),
            secret: false,
        }
    }

    #[test]
    fn root_is_order_independent_and_content_bound() {
        let a = Workspace::new(&[f("/a", "1"), f("/b", "2")]).unwrap();
        let b = Workspace::new(&[f("/b", "2"), f("/a", "1")]).unwrap();
        let c = Workspace::new(&[f("/a", "1"), f("/b", "3")]).unwrap();
        assert_eq!(a.root(), b.root());
        assert_ne!(a.root(), c.root());
        let mut d = a.clone();
        d.write("/a", "1", true).unwrap();
        assert_ne!(a.root(), d.root(), "secret label is committed");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Workspace::new(&[f("/a", "1"), f("/a", "2")]).is_err());
        assert!(Workspace::new(&[f("a", "1")]).is_err());
        assert!(Workspace::new(&[f("/a/../b", "1")]).is_err());
    }
}
