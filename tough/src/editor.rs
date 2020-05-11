// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datastore::Datastore;
use crate::error::{self, Result};
use crate::key_source::KeySource;
use crate::root_digest::{RootDigest, RootKeys};
use crate::schema::{
    Hashes, Role, RoleType, Root, Signature, Signed, Snapshot, SnapshotMeta, Target, Targets,
    Timestamp, TimestampMeta,
};
use crate::transport::{TargetMapTransport, Transport};
use crate::{Repository, Settings};
use maplit::hashmap;
use olpc_cjson::CanonicalFormatter;
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use snafu::ResultExt;
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use url::Url;

/// An in-memory, unsigned TUF repository
///
/// This is provided as means to create and update a repository, which can then be signed.
#[derive(Debug)]
pub struct RepositoryEditor {
    pub snapshot: Snapshot,
    pub timestamp: Timestamp,
    pub targets: Targets,
    targets_meta: TargetMapTransport,
}

impl RepositoryEditor {
    pub fn new(snapshot: Snapshot, timestamp: Timestamp, targets: Targets) -> RepositoryEditor {
        RepositoryEditor {
            snapshot,
            timestamp,
            targets,
            targets_meta: TargetMapTransport {
                targets: HashMap::new(),
            },
        }
    }

    //pub fn from_path<P>(path: P)
    //where
    //    P: AsRef<Path>,
    //{
    //}

    pub fn add_target<P>(&mut self, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        // Get the absolute path to the given target
        let path = std::fs::canonicalize(path.as_ref()).context(error::AbsolutePath {
            path: path.as_ref().to_owned(),
        })?;

        // Build a Target and add it to the Targets struct
        let (target_name, target) =
            Target::from_path(&path).context(error::TargetFromPath { path: &path })?;
        self.targets
            .targets
            .insert(target_name.clone(), target.clone());

        // Add the target metadata to the TargetMapTransport
        // TODO: NOTE HERE ABOUT BOTH FORMS
        let target_sha256 = &target.hashes.sha256.clone().into_vec();
        self.targets_meta.targets.insert(
            format!("{}.{}", hex::encode(target_sha256), target_name),
            path.to_owned(),
        );
        self.targets_meta
            .targets
            .insert(target_name, path.to_owned());

        Ok(())
    }

    pub fn build<'a, P1, P2, T>(
        &mut self,
        root_path: P1,
        keys: Vec<Box<dyn KeySource>>,
        datastore: P2,
    ) -> Result<Repository<'a, T>>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
        T: Transport,
    {
        let root_path = root_path.as_ref().to_owned();
        let root_buf = std::fs::read(&root_path).context(error::FileRead { path: &root_path })?;
        let signed_root = serde_json::from_slice::<Signed<Root>>(&root_buf)
            .context(error::FileParseJson { path: &root_path })?;
        let root_digest = RootDigest::load(&root_path)?;
        let key_pairs = root_digest.load_keys(&keys)?;

        let rng = SystemRandom::new();

        let mut signed_targets = Signed {
            signed: self.targets.clone(),
            signatures: Vec::new(),
        };
        let (targets_sha256, targets_length) = RepositoryEditor::sign_role(
            datastore.as_ref(),
            &root_digest.root,
            &key_pairs,
            &mut signed_targets,
            self.targets.version,
            &rng,
            "targets.json",
        )?;

        // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=
        // Update and sign snapshot
        self.snapshot.meta = hashmap! {
            "root.json".to_owned() => SnapshotMeta {
                hashes: Some(Hashes {
                    sha256: root_digest.digest.to_vec().into(),
                    _extra: HashMap::new(),
                }),
                length: Some(root_digest.size),
                version: root_digest.root.version,
                _extra: HashMap::new(),
            },
            "targets.json".to_owned() => SnapshotMeta {
                hashes: Some(Hashes {
                    sha256: targets_sha256.to_vec().into(),
                    _extra: HashMap::new(),
                }),
                length: Some(targets_length),
                version: self.targets.version,
                _extra: HashMap::new(),
            },
        };
        let mut signed_snapshot = Signed {
            signed: self.snapshot.clone(),
            signatures: Vec::new(),
        };
        let (snapshot_sha256, snapshot_length) = RepositoryEditor::sign_role(
            datastore.as_ref(),
            &root_digest.root,
            &key_pairs,
            &mut signed_snapshot,
            self.snapshot.version,
            &rng,
            "snapshot.json",
        )?;

        // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=
        // Update and sign timestamp
        self.timestamp.meta = hashmap! {
            "snapshot.json".to_owned() => TimestampMeta {
                hashes: Hashes {
                    sha256: snapshot_sha256.to_vec().into(),
                    _extra: HashMap::new(),
                },
                length: snapshot_length,
                version: self.snapshot.version,
                _extra: HashMap::new(),
            }
        };
        let mut signed_timestamp = Signed {
            signed: self.timestamp.clone(),
            signatures: Vec::new(),
        };
        let (_timestamp_sha256, _timestamp_length) = RepositoryEditor::sign_role(
            datastore.as_ref(),
            &root_digest.root,
            &key_pairs,
            &mut signed_timestamp,
            self.timestamp.version,
            &rng,
            "timestamp.json",
        )?;

        let expires_iter = [
            (root_digest.root.expires, RoleType::Root),
            (self.timestamp.expires, RoleType::Timestamp),
            (self.snapshot.expires, RoleType::Snapshot),
            (self.targets.expires, RoleType::Targets),
        ];
        let (earliest_expiration, earliest_expiration_role) =
            expires_iter.iter().min_by_key(|tup| tup.0).unwrap();

        let repo = Repository {
            transport: TargetMapTransport {
                targets: HashMap::new(),
            },
            consistent_snapshot: true,
            datastore: Datastore::new(datastore.as_ref()),
            earliest_expiration: earliest_expiration.to_owned(),
            earliest_expiration_role: *earliest_expiration_role,
            root: signed_root,
            snapshot: signed_snapshot,
            timestamp: signed_timestamp,
            targets: signed_targets,
            targets_base_url: Url::parse("target_map:///").context(error::ParseUrl {
                url: "target_map:///",
            })?,
        };
        Ok(repo)
    }

    fn sign_role<T, P>(
        outdir: P,
        root: &Root,
        keys: &RootKeys,
        role: &mut Signed<T>,
        version: NonZeroU64,
        rng: &dyn SecureRandom,
        filename: &'static str,
    ) -> Result<([u8; SHA256_OUTPUT_LEN], u64)>
    where
        T: Role + Serialize,
        P: AsRef<Path>,
    {
        let metadir = outdir.as_ref().join("metadata");
        std::fs::create_dir_all(&metadir).context(error::FileCreate { path: &metadir })?;

        let path = metadir.join(
            if T::TYPE != RoleType::Timestamp && root.consistent_snapshot {
                format!("{}.{}", version, filename)
            } else {
                filename.to_owned()
            },
        );

        let mut role = Signed {
            signed: role,
            signatures: Vec::new(),
        };

        let role_type = T::TYPE;
        if let Some(role_keys) = root.roles.get(&role_type) {
            for (keyid, key) in keys {
                if role_keys.keyids.contains(&keyid) {
                    let mut data = Vec::new();
                    let mut ser = serde_json::Serializer::with_formatter(
                        &mut data,
                        CanonicalFormatter::new(),
                    );
                    role.signed
                        .serialize(&mut ser)
                        .context(error::SerializeRole)?;
                    let sig = key.sign(&data, rng)?;
                    role.signatures.push(Signature {
                        keyid: keyid.clone(),
                        sig: sig.into(),
                    });
                }
            }
        }

        let mut buf = serde_json::to_vec_pretty(&role).context(error::SerializeSignedRole)?;
        buf.push(b'\n');
        std::fs::write(&path, &buf).context(error::FileCreate { path: &path })?;

        let mut sha256 = [0; SHA256_OUTPUT_LEN];
        sha256.copy_from_slice(digest(&SHA256, &buf).as_ref());
        Ok((sha256, buf.len() as u64))
    }
}

//impl TryFrom<Repository<'a>> for RepositoryEditor {}
