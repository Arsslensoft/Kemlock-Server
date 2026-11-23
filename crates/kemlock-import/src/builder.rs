// Partly ported from Bitwarden's clients (https://github.com/bitwarden/clients):
//   libs/importer/src/importers/base-importer.ts (processFolder),
//   at commit f9c68e008ba91dc19edf519305a82d3a994a7baa.
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Builds an [`ImportBatch`] under the limits: it keeps the folder tree, the shared vaults and the
//! count of entries, and drops (and counts) what is over the entry limit.

use std::collections::HashMap;

use crate::error::{ImportError, Result};
use crate::limits::Limits;
use crate::model::{
    Card, Code, Format, Identity, ImportBatch, ImportFile, ItemKind, ItemRef, Login, Note,
    SharedKind, SharedVault, SkipReason, Skipped, SshKey,
};

/// Collects what a parser reads.
#[derive(Debug)]
pub struct Builder<'a> {
    /// The batch so far.
    pub batch: ImportBatch,
    limits: &'a Limits,
    folder_index: HashMap<String, usize>,
    space_index: HashMap<String, usize>,
    over_limit: usize,
    skipped_over_limit: usize,
}

impl<'a> Builder<'a> {
    /// An empty builder for `format`.
    pub fn new(format: Format, limits: &'a Limits) -> Builder<'a> {
        Builder {
            batch: ImportBatch::new(format),
            limits,
            folder_index: HashMap::new(),
            space_index: HashMap::new(),
            over_limit: 0,
            skipped_over_limit: 0,
        }
    }

    /// The limits in force.
    pub fn limits(&self) -> &'a Limits {
        self.limits
    }

    /// Whether the entry limit is reached; a parser may stop reading then, after counting the rest
    /// with [`Builder::note_unread`].
    pub fn full(&self) -> bool {
        self.batch.entry_count() >= self.limits.max_entries
    }

    /// Counts `count` entries the parser did not read because the batch is full.
    pub fn note_unread(&mut self, count: usize) {
        self.over_limit = self.over_limit.saturating_add(count);
    }

    fn room(&mut self) -> bool {
        if self.full() {
            self.over_limit = self.over_limit.saturating_add(1);
            false
        } else {
            true
        }
    }

    /// Adds a login; `None` when the batch is full.
    pub fn login(&mut self, login: Login) -> Option<ItemRef> {
        if !self.room() {
            return None;
        }
        self.batch.logins.push(login);
        Some(ItemRef {
            kind: ItemKind::Login,
            index: self.batch.logins.len() - 1,
        })
    }

    /// Adds a code; `None` when the batch is full.
    pub fn code(&mut self, code: Code) -> Option<ItemRef> {
        if !self.room() {
            return None;
        }
        self.batch.codes.push(code);
        Some(ItemRef {
            kind: ItemKind::Code,
            index: self.batch.codes.len() - 1,
        })
    }

    /// Adds a note; `None` when the batch is full.
    pub fn note(&mut self, note: Note) -> Option<ItemRef> {
        if !self.room() {
            return None;
        }
        self.batch.notes.push(note);
        Some(ItemRef {
            kind: ItemKind::Note,
            index: self.batch.notes.len() - 1,
        })
    }

    /// Adds a card; `None` when the batch is full.
    pub fn card(&mut self, card: Card) -> Option<ItemRef> {
        if !self.room() {
            return None;
        }
        self.batch.cards.push(card);
        Some(ItemRef {
            kind: ItemKind::Card,
            index: self.batch.cards.len() - 1,
        })
    }

    /// Adds an identity; `None` when the batch is full.
    pub fn identity(&mut self, identity: Identity) -> Option<ItemRef> {
        if !self.room() {
            return None;
        }
        self.batch.identities.push(identity);
        Some(ItemRef {
            kind: ItemKind::Identity,
            index: self.batch.identities.len() - 1,
        })
    }

    /// Adds an SSH key; `None` when the batch is full.
    pub fn ssh_key(&mut self, key: SshKey) -> Option<ItemRef> {
        if !self.room() {
            return None;
        }
        self.batch.ssh_keys.push(key);
        Some(ItemRef {
            kind: ItemKind::SshKey,
            index: self.batch.ssh_keys.len() - 1,
        })
    }

    /// Adds a file. The files of one batch are bounded by what the ZIP and KDBX readers allow, and
    /// by the entry limit here.
    pub fn file(
        &mut self,
        name: &str,
        media_type: Option<&str>,
        data: Vec<u8>,
        owner: Option<ItemRef>,
    ) {
        if self.batch.files.len() >= self.limits.max_entries {
            self.skip(Some(name), SkipReason::FileOverLimit, None);
            return;
        }
        self.batch.files.push(ImportFile {
            name: name.to_string(),
            media_type: media_type.map(str::to_string),
            data,
            owner,
        });
    }

    /// The folder at `path` (parts separated by `/` or `\`, as Bitwarden's `processFolder` reads
    /// them), made with its parents when new; `None` for a blank path. A path deeper than the
    /// limit keeps its first levels and folds the rest into the last one.
    pub fn folder(&mut self, path: &str) -> Option<usize> {
        let normalised = path.replace('\\', "/");
        let mut parts: Vec<String> = normalised
            .split('/')
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect();
        if parts.is_empty() {
            return None;
        }
        let depth = self.limits.max_folder_depth.max(1);
        if parts.len() > depth {
            let tail = parts.split_off(depth - 1).join(" / ");
            parts.push(tail);
        }
        let mut parent: Option<usize> = None;
        let mut full = String::new();
        for part in parts {
            if !full.is_empty() {
                full.push('/');
            }
            full.push_str(&part);
            let known = self.folder_index.get(&full).copied();
            let index = match known {
                Some(index) => index,
                None => {
                    if self.batch.folders.len() >= self.limits.max_entries {
                        return parent;
                    }
                    let index = self.batch.folders.len();
                    self.batch.folders.push(crate::model::Folder {
                        name: part,
                        parent,
                        path: full.clone(),
                    });
                    self.folder_index.insert(full.clone(), index);
                    index
                }
            };
            parent = Some(index);
        }
        parent
    }

    /// The shared vault known by `key`, added with `name` and `kind` when new. `None` when there
    /// are too many.
    pub fn space(&mut self, key: &str, name: &str, kind: SharedKind) -> Option<usize> {
        if let Some(index) = self.space_index.get(key) {
            return Some(*index);
        }
        if self.batch.spaces.len() >= self.limits.max_entries {
            return None;
        }
        let index = self.batch.spaces.len();
        self.batch.spaces.push(SharedVault {
            name: name.to_string(),
            kind,
            source_id: Some(key.to_string()),
        });
        self.space_index.insert(key.to_string(), index);
        Some(index)
    }

    /// Records an entry that was left out.
    pub fn skip(&mut self, name: Option<&str>, reason: SkipReason, detail: Option<&str>) {
        if self.batch.skipped.len() >= self.limits.max_entries {
            self.skipped_over_limit = self.skipped_over_limit.saturating_add(1);
            return;
        }
        self.batch.skipped.push(Skipped {
            name: name.filter(|n| !n.trim().is_empty()).map(str::to_string),
            reason,
            detail: detail.map(str::to_string),
            count: 1,
        });
    }

    /// Ends the batch. The entries over the limit and the skips over the limit are each recorded
    /// as one skipped item with a count. An export with no entries and nothing skipped is
    /// [`ImportError::Empty`].
    pub fn finish(mut self) -> Result<ImportBatch> {
        if self.over_limit > 0 {
            self.batch.skipped.push(Skipped {
                name: None,
                reason: SkipReason::OverLimit,
                detail: Some(format!("the limit is {} entries", self.limits.max_entries)),
                count: self.over_limit,
            });
        }
        if self.skipped_over_limit > 0 {
            self.batch.skipped.push(Skipped {
                name: None,
                reason: SkipReason::Other,
                detail: Some("more skipped entries than are listed".to_string()),
                count: self.skipped_over_limit,
            });
        }
        if self.batch.entry_count() == 0 && self.batch.skipped.is_empty() {
            return Err(ImportError::Empty);
        }
        Ok(self.batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builder(limits: &Limits) -> Builder<'_> {
        Builder::new(Format::ChromeCsv, limits)
    }

    #[test]
    fn folders_nest_and_are_reused() {
        let limits = Limits::default();
        let mut b = builder(&limits);
        let c = b.folder("a\\b/c").expect("folder");
        assert_eq!(b.batch.folders.len(), 3);
        assert_eq!(b.batch.folders[c].path, "a/b/c");
        assert_eq!(b.batch.folders[c].name, "c");
        let parent = b.batch.folders[c].parent.expect("parent");
        assert_eq!(b.batch.folders[parent].path, "a/b");
        assert_eq!(b.folder("/a/b/"), Some(parent));
        assert_eq!(b.batch.folders.len(), 3);
        assert_eq!(b.folder("  / "), None);
        assert_eq!(b.batch.folders[0].parent, None);
    }

    #[test]
    fn deep_folders_fold_into_the_last_level() {
        let limits = Limits {
            max_folder_depth: 3,
            ..Limits::default()
        };
        let mut b = builder(&limits);
        let leaf = b.folder("a/b/c/d/e").expect("folder");
        assert_eq!(b.batch.folders.len(), 3);
        assert_eq!(b.batch.folders[leaf].name, "c / d / e");
    }

    #[test]
    fn entries_over_the_limit_are_dropped_and_counted_once() {
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        let mut b = builder(&limits);
        assert!(b.login(Login::default()).is_some());
        assert!(b.note(Note::default()).is_some());
        assert!(b.full());
        assert!(b.card(Card::default()).is_none());
        assert!(b.login(Login::default()).is_none());
        b.note_unread(5);
        let batch = b.finish().expect("batch");
        assert_eq!(batch.entry_count(), 2);
        assert_eq!(batch.skipped.len(), 1);
        assert_eq!(batch.skipped[0].reason, SkipReason::OverLimit);
        assert_eq!(batch.skipped[0].count, 7);
    }

    #[test]
    fn spaces_are_keyed() {
        let limits = Limits::default();
        let mut b = builder(&limits);
        let a = b.space("v1", "Family", SharedKind::Vault);
        assert_eq!(b.space("v1", "Other name", SharedKind::Vault), a);
        assert_eq!(b.space("v2", "Work", SharedKind::Collection), Some(1));
        assert_eq!(b.batch.spaces[0].name, "Family");
    }

    #[test]
    fn nothing_in_it_is_empty_but_only_skips_is_a_batch() {
        let limits = Limits::default();
        let b = builder(&limits);
        assert_eq!(b.finish(), Err(ImportError::Empty));
        let mut b = builder(&limits);
        b.skip(Some("Old"), SkipReason::Trashed, None);
        b.skip(Some("  "), SkipReason::Trashed, None);
        let batch = b.finish().expect("batch");
        assert_eq!(batch.skipped_count(), 2);
        assert_eq!(batch.skipped[1].name, None);
    }

    #[test]
    fn files_keep_their_owner_and_stop_at_the_limit() {
        let limits = Limits {
            max_entries: 1,
            ..Limits::default()
        };
        let mut b = builder(&limits);
        let owner = b.login(Login::default());
        b.file("a.txt", Some("text/plain"), vec![1], owner);
        b.file("b.txt", None, vec![2], owner);
        let batch = b.finish().expect("batch");
        assert_eq!(batch.files.len(), 1);
        assert_eq!(batch.files[0].owner, owner);
        assert_eq!(batch.skipped[0].reason, SkipReason::FileOverLimit);
    }
}
