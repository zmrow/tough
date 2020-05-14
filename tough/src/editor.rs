// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datastore::Datastore;
use crate::error::{self, Result};
use crate::key_source::KeySource;
use crate::schema::decoded::{Decoded, Hex};
use crate::schema::{
    Hashes, Role, Root, Signature, Signed, Snapshot, SnapshotMeta, Target, Targets, Timestamp,
    TimestampMeta,
};
use crate::sign::Sign;
use crate::transport::{TargetMapTransport, Transport};
use crate::{Repository, Settings};
use chrono::{DateTime, Utc};
use maplit::hashmap;
use olpc_cjson::CanonicalFormatter;
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::Value;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use url::Url;

const SPEC_VERSION: &str = "1.0.0";

type RootKeys = HashMap<Decoded<Hex>, Box<dyn Sign>>;

#[derive(Debug)]
struct SignedRole<T> {
    signed: Signed<T>,
    buffer: Vec<u8>,
    sha256: [u8; SHA256_OUTPUT_LEN],
    length: u64,
}

impl SignedRole<Root> {
    fn root(&self) -> &Root {
        &self.signed.signed
    }
}

#[derive(Debug)]
pub struct SignedRepository {
    root: SignedRole<Root>,
    snapshot: SignedRole<Snapshot>,
    targets: SignedRole<Targets>,
    timestamp: SignedRole<Timestamp>,
}

#[derive(Debug, Default)]
pub struct RepositoryEditor {
    root_path: PathBuf,
    root: Option<SignedRole<Root>>,

    old_snapshot_version: Option<NonZeroU64>,
    snapshot_version: Option<NonZeroU64>,
    snapshot_expires: Option<DateTime<Utc>>,
    snapshot_extra: Option<HashMap<String, Value>>,

    new_targets: Option<HashMap<String, Target>>,
    existing_targets: Option<HashMap<String, Target>>,
    targets_version: Option<NonZeroU64>,
    targets_expires: Option<DateTime<Utc>>,
    targets_extra: Option<HashMap<String, Value>>,

    timestamp_version: Option<NonZeroU64>,
    timestamp_expires: Option<DateTime<Utc>>,
    timestamp_extra: Option<HashMap<String, Value>>,
}

//impl From<Repository> for RepositoryEditor {
//    fn from(root_path: PathBuf, repository: Repository) -> Self {
//        RepositoryEditor {
//            snapshot: repository.snapshot.signed,
//            targets: repository.targets.signed,
//            timestamp: repository.timestamp.signed,
//            root: repository.root.signed,
//            signed_root: repository.root,
//        }
//    }
//}

impl RepositoryEditor {
    pub fn new<P>(root_path: P) -> Result<RepositoryEditor>
    where
        P: AsRef<Path>,
    {
        // Read and parse the root.json. Without a good root, it doesn't
        // make sense to continue
        let root_path = root_path.as_ref();
        let root_buf = std::fs::read(root_path).context(error::FileRead { path: root_path })?;
        let root = serde_json::from_slice::<Signed<Root>>(&root_buf)
            .context(error::FileParseJson { path: root_path })?;
        let mut digest = [0; SHA256_OUTPUT_LEN];
        digest.copy_from_slice(ring::digest::digest(&SHA256, &root_buf).as_ref());

        let signed_root = SignedRole {
            signed: root,
            buffer: root_buf,
            sha256: digest,
            length: root_buf.len() as u64,
        };

        Ok(RepositoryEditor {
            root_path: root_path.to_owned(),
            root: Some(signed_root),
            ..Default::default()
        })
    }

    pub fn snapshot(&mut self, snapshot: Snapshot) -> Result<&mut Self> {
        ensure!(
            snapshot.spec_version == SPEC_VERSION,
            error::SpecVersion {
                given: snapshot.spec_version,
                supported: SPEC_VERSION
            }
        );
        self.snapshot_extra = Some(snapshot._extra);
        Ok(self)
    }

    pub fn timestamp(&mut self, timestamp: Timestamp) -> Result<&mut Self> {
        ensure!(
            timestamp.spec_version == SPEC_VERSION,
            error::SpecVersion {
                given: timestamp.spec_version,
                supported: SPEC_VERSION
            }
        );
        self.timestamp_extra = Some(timestamp._extra);
        Ok(self)
    }

    pub fn targets(&mut self, targets: Targets) -> Result<&mut Self> {
        ensure!(
            targets.spec_version == SPEC_VERSION,
            error::SpecVersion {
                given: targets.spec_version,
                supported: SPEC_VERSION
            }
        );

        // Hold on to the existing targets
        self.existing_targets = Some(targets.targets);
        self.targets_extra = Some(targets._extra);
        Ok(self)
    }

    pub fn add_target<P>(&mut self, target_path: P) -> Result<&mut Self>
    where
        P: AsRef<Path>,
    {
        let new_targets = self.new_targets.unwrap_or_else(|| HashMap::new());
        let target_path = target_path.as_ref();
        // Build a Target from the path given. If it is not a file, this will fail
        let target =
            Target::from_path(target_path).context(error::TargetFromPath { path: target_path })?;

        // Get the file name as a string
        let target_name = target_path
            .file_name()
            .context(error::NoFileName { path: target_path })?
            .to_str()
            .context(error::PathUtf8 { path: target_path })?
            .to_owned();

        new_targets.insert(target_name, target);

        Ok(self)
    }

    pub fn add_targets<P>(&mut self, targets: Vec<P>) -> Result<&mut Self>
    where
        P: AsRef<Path>,
    {
        for target in targets {
            self.add_target(target)?;
        }
        Ok(self)
    }

    pub fn snapshot_version(&mut self, snapshot_version: NonZeroU64) -> &mut Self {
        self.snapshot_version = Some(snapshot_version);
        self
    }

    pub fn snapshot_expires(&mut self, snapshot_expires: DateTime<Utc>) -> &mut Self {
        self.snapshot_expires = Some(snapshot_expires);
        self
    }

    pub fn targets_version(&mut self, targets_version: NonZeroU64) -> &mut Self {
        self.targets_version = Some(targets_version);
        self
    }

    pub fn targets_expires(&mut self, targets_expires: DateTime<Utc>) -> &mut Self {
        self.targets_expires = Some(targets_expires);
        self
    }

    pub fn timestamp_version(&mut self, timestamp_version: NonZeroU64) -> &mut Self {
        self.timestamp_version = Some(timestamp_version);
        self
    }

    pub fn timestamp_expires(&mut self, timestamp_expires: DateTime<Utc>) -> &mut Self {
        self.timestamp_expires = Some(timestamp_expires);
        self
    }

    pub fn sign(self, keys: Vec<Box<dyn KeySource>>) -> Result<SignedRepository> {
        let rng = SystemRandom::new();
        let root_keys = self.get_root_keys(keys)?;

        //Build the Targets metadata, the sign it
        let targets = self
            .build_targets()
            .and_then(|targets| self.sign_role(targets, &root_keys, &rng))?;
        //Build Snapshot
        //Build Timestamp
        //
        //let signed_targets = sign_metadata(targets)
        Ok(())
    }

    fn get_root_keys(&self, keys: Vec<Box<dyn KeySource>>) -> Result<RootKeys> {
        let root = self.root.context(error::Missing { field: "root" })?.root();
        let mut root_keys = RootKeys::new();

        for source in keys {
            let key_pair = source.as_sign().context(error::KeyPairFromKeySource)?;

            if let Some(key_id) = root.key_id(key_pair.as_ref()) {
                root_keys.insert(key_id, key_pair);
            }
        }
        ensure!(!root_keys.is_empty(), error::KeysNotFoundInRoot);
        Ok(root_keys)
    }

    fn build_targets(&self) -> Result<Targets> {
        let version = self.targets_version.context(error::Missing {
            field: "targets version",
        })?;
        let expires = self.targets_expires.context(error::Missing {
            field: "targets expiration",
        })?;

        // BEWARE!!! We are allowing targets to be empty! While this isn't
        // the most common use case, it's possible this is what a user wants.
        // If it's important to have a non-empty targets, the object can be
        // inspected by the calling code.
        let mut targets: HashMap<String, Target> = HashMap::new();
        if let Some(existing_targets) = self.existing_targets {
            targets.extend(existing_targets);
        }
        if let Some(new_targets) = self.new_targets {
            targets.extend(new_targets);
        }
        //ensure!(!targets.is_empty(), error::NoTargets);

        let _extra = self.targets_extra.unwrap_or_else(|| HashMap::new());
        Ok(Targets {
            spec_version: SPEC_VERSION.to_string(),
            version,
            expires,
            targets,
            _extra,
        })
    }

    fn build_snapshot(&self, targets: SignedRole<Targets>, root: Signed<Root>) {}

    fn sign_role<T>(
        &self,
        role: T,
        keys: &RootKeys,
        rng: &dyn SecureRandom,
    ) -> Result<SignedRole<T>>
    where
        T: Role + Serialize,
    {
        let root = self.root.context(error::Missing { field: "root" })?.root();
        let role_keys = root.roles.get(&T::TYPE).context(error::NoRoleKeysinRoot {
            role: &T::TYPE.to_string(),
        })?;
        let (signing_key_id, signing_key) = keys
            .iter()
            .find(|(keyid, signing_key)| role_keys.keyids.contains(&keyid))
            .context(error::SigningKeysNotFound {
                role: &T::TYPE.to_string(),
            })?;

        let mut role = Signed {
            signed: role,
            signatures: Vec::new(),
        };

        let mut data = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
        role.signed
            .serialize(&mut ser)
            .context(error::SerializeRole)?;
        let sig = signing_key.sign(&data, rng)?;
        role.signatures.push(Signature {
            keyid: signing_key_id.clone(),
            sig: sig.into(),
        });

        let mut buffer = serde_json::to_vec_pretty(&role).context(error::SerializeSignedRole)?;
        buffer.push(b'\n');

        let mut sha256 = [0; SHA256_OUTPUT_LEN];
        sha256.copy_from_slice(digest(&SHA256, &buffer).as_ref());

        let signed_role = SignedRole {
            signed: role,
            buffer,
            sha256,
            length: buffer.len() as u64,
        };

        Ok(signed_role)
    }

    //fn build_role(&self, context: BuildRoleContext) -> CompleteRole {
    //    let incomplete_role = if context.existing_role.is_some() {
    //        self.update_existing_role(&context)
    //    } else {
    //        self.build_bare_role(&context)
    //    };
    //    match context.role {
    //        RoleType::Snapshot => if let Some(current_snapshot) = self.snapshot {},
    //        RoleType::Targets => {}
    //        RoleType::Timestamp => {}
    //    }
    //}

    //fn create_role(&self, context: CreateContext) -> Result<ConcreteRole> {
    //    match role {
    //        RoleType::Snapshot => {
    //            let version = self.snapshot_version.context(error::Missing {
    //                field: "snapshot version",
    //            })?;
    //            let expires = self.snapshot_expires.context(error::Missing {
    //                field: "snapshot expiration",
    //            })?;

    //            let snapshot = Snapshot::new(SPEC_VERSION.to_string(), version, expires);
    //            Ok(ConcreteRole::Snapshot(snapshot))
    //        }
    //        RoleType::Targets => {
    //            let version = self.targets_version.context(error::Missing {
    //                field: "targets version",
    //            })?;
    //            let expires = self.targets_expires.context(error::Missing {
    //                field: "targets expiration",
    //            })?;

    //            let targets = Targets::new(SPEC_VERSION.to_string(), version, expires);
    //            Ok(ConcreteRole::Targets(targets))
    //        }
    //        RoleType::Timestamp => {
    //            let version = self.timestamp_version.context(error::Missing {
    //                field: "timestamp version",
    //            })?;
    //            let expires = self.timestamp_expires.context(error::Missing {
    //                field: "timestamp expiration",
    //            })?;

    //            let timestamp = Timestamp::new(SPEC_VERSION.to_string(), version, expires);
    //            Ok(ConcreteRole::Timestamp(timestamp))
    //        }
    //    }
    //}
    //fn create_role(
    //    &self,
    //    role: RoleType,
    //    version: Option<NonZeroU64>,
    //    expires: Option<DateTime<Utc>>,
    //) -> Result<ConcreteRole> {
    //    match role {
    //        RoleType::Snapshot => {
    //            let version = self.snapshot_version.context(error::Missing {
    //                field: "snapshot version",
    //            })?;
    //            let expires = self.snapshot_expires.context(error::Missing {
    //                field: "snapshot expiration",
    //            })?;

    //            let snapshot = Snapshot::new(SPEC_VERSION.to_string(), version, expires);
    //            Ok(ConcreteRole::Snapshot(snapshot))
    //        }
    //        RoleType::Targets => {
    //            let version = self.targets_version.context(error::Missing {
    //                field: "targets version",
    //            })?;
    //            let expires = self.targets_expires.context(error::Missing {
    //                field: "targets expiration",
    //            })?;

    //            let targets = Targets::new(SPEC_VERSION.to_string(), version, expires);
    //            Ok(ConcreteRole::Targets(targets))
    //        }
    //        RoleType::Timestamp => {
    //            let version = self.timestamp_version.context(error::Missing {
    //                field: "timestamp version",
    //            })?;
    //            let expires = self.timestamp_expires.context(error::Missing {
    //                field: "timestamp expiration",
    //            })?;

    //            let timestamp = Timestamp::new(SPEC_VERSION.to_string(), version, expires);
    //            Ok(ConcreteRole::Timestamp(timestamp))
    //        }
    //    }
    //}

    // -> SignedRepository

    //fn build_role(&self, role: Role) {
    //    match role {
    //        Role::Snapshot => {}
    //        Role::Targets => {}
    //        Role::Timestamp => {}
    //    }
    //}

    //fn build_role_inner(
    //    &self,
    //    role: Role,
    //    expires: Option<DateTime<Utc>>,
    //    version: Option<NonZeroU64>,
    //) {
    //    let current_role = match role {
    //        Role::Snapshot => self.snapshot,
    //        Role::Targets => self.targets,
    //        Role::Timestamp => self.timestamp,
    //    };

    //    match role {
    //        Role::Snapshot => self.snapshot,
    //        Role::Targets => self.targets,
    //        Role::Timestamp => self.timestamp,
    //    }

    //    if let Some(existing_role) = current_role {
    //        update_role(current_role.clone(), version, expires)
    //    } else {
    //        create_role(role, version, expires)
    //    }
    //}

    //fn build_target_data(&self) -> Result<Vec<TargetData>> {
    //    let mut target_data = Vec::new();

    //    for target in &self.target_list {
    //        // Get the absolute path to the given target
    //        let target_path =
    //            std::fs::canonicalize(&target).context(error::AbsolutePath { path: &target })?;

    //        // Get the file name as a string
    //        let target_name = target_path
    //            .file_name()
    //            .context(error::NoFileName { path: &target_path })?
    //            .to_str()
    //            .context(error::PathUtf8 { path: &target_path })?
    //            .to_owned();

    //        // Get the name of the file and the Target object from the target path
    //        let (target_name, target) = Target::from_path(&target_path)
    //            .context(error::TargetFromPath { path: &target_path })?;

    //        target_data.push(TargetData {
    //            path: target_path,
    //            target,
    //            name: target_name,
    //        })
    //    }
    //    Ok(target_data)
    //}

    //fn build_targets_role(&self, target_data: &Vec<TargetData>) -> Result<Targets> {
    //    let mut targets_meta = if let Some(targets) = &self.targets {
    //        let mut new_targets = targets.clone();
    //        if let Some(version) = self.targets_version {
    //            new_targets.version = version;
    //        }
    //        if let Some(expires) = self.targets_expires {
    //            new_targets.expires = expires;
    //        }

    //        new_targets
    //    } else {
    //        let version = self.targets_version.context(error::Missing {
    //            field: "targets version",
    //        })?;
    //        let expires = self.targets_expires.context(error::Missing {
    //            field: "targets expiration",
    //        })?;

    //        Targets {
    //            spec_version: SPEC_VERSION.to_string(),
    //            version,
    //            expires,
    //            targets: HashMap::new(),
    //            _extra: HashMap::new(),
    //        }
    //    };

    //    // Add all the new targets to the Targets struct
    //    for target in target_data {
    //        targets_meta
    //            .targets
    //            .insert(target.name.clone(), target.target.clone());
    //    }

    //    Ok(targets_meta)
    //}

    //fn build_snapshot_meta(
    //    &self,
    //    root: &SignedRole<Root>,
    //    targets_meta: &SignedRole<Targets>,
    //) -> Result<Snapshot> {
    //    let mut snapshot_meta = if let Some(snapshot) = &self.snapshot {
    //        let mut new_snapshot = snapshot.clone();
    //        if let Some(version) = self.snapshot_version {
    //            new_snapshot.version = version;
    //        }
    //        if let Some(expires) = self.snapshot_expires {
    //            new_snapshot.expires = expires;
    //        }

    //        new_snapshot
    //    } else {
    //        let version = self.snapshot_version.context(error::Missing {
    //            field: "targets version",
    //        })?;
    //        let expires = self.snapshot_expires.context(error::Missing {
    //            field: "targets expiration",
    //        })?;

    //        Snapshot {
    //            spec_version: SPEC_VERSION.to_string(),
    //            version,
    //            expires,
    //            meta: HashMap::new(),
    //            _extra: HashMap::new(),
    //        }
    //    };

    //    let root_meta = SnapshotMeta {
    //        length: Some(root.length),
    //        hashes: Some(Hashes {
    //            sha256: root.sha256.to_vec().into(),
    //            _extra: HashMap::new(),
    //        }),
    //        version: root.signed.signed.version,
    //        _extra: HashMap::new(),
    //    };

    //    let targets_meta = SnapshotMeta {
    //        length: Some(targets_meta.length),
    //        hashes: Some(Hashes {
    //            sha256: targets_meta.sha256.to_vec().into(),
    //            _extra: HashMap::new(),
    //        }),
    //        version: targets_meta.signed.signed.version,
    //        _extra: HashMap::new(),
    //    };

    //    snapshot_meta.meta.insert("root.json".to_owned(), root_meta);
    //    snapshot_meta
    //        .meta
    //        .insert("targets.json".to_owned(), targets_meta);
    //    Ok(snapshot_meta)
    //}

    //fn build_timestamp_meta(&self, snapshot_meta: &SignedRole<Snapshot>) -> Result<Timestamp> {
    //    let mut timestamp_meta = if let Some(timestamp) = &self.timestamp {
    //        let mut new_timestamp = timestamp.clone();
    //        if let Some(version) = self.timestamp_version {
    //            new_timestamp.version = version;
    //        }
    //        if let Some(expires) = self.timestamp_expires {
    //            new_timestamp.expires = expires;
    //        }

    //        new_timestamp
    //    } else {
    //        let version = self.timestamp_version.context(error::Missing {
    //            field: "targets version",
    //        })?;
    //        let expires = self.timestamp_expires.context(error::Missing {
    //            field: "targets expiration",
    //        })?;

    //        Timestamp {
    //            spec_version: SPEC_VERSION.to_string(),
    //            version,
    //            expires,
    //            meta: HashMap::new(),
    //            _extra: HashMap::new(),
    //        }
    //    };

    //    let snapshot_meta = TimestampMeta {
    //        length: snapshot_meta.length,
    //        hashes: Hashes {
    //            sha256: snapshot_meta.sha256.to_vec().into(),
    //            _extra: HashMap::new(),
    //        },
    //        version: snapshot_meta.signed.signed.version,
    //        _extra: HashMap::new(),
    //    };

    //    timestamp_meta
    //        .meta
    //        .insert("snapshot.json".to_owned(), snapshot_meta);
    //    Ok(timestamp_meta)
    //}

    //pub fn build<'a, P1>(
    //    &mut self,
    //    root_path: P1,
    //    keys: Vec<Box<dyn KeySource>>,
    //    datastore_path: &'a Path,
    //) -> Result<Repository<'a, TargetMapTransport>>
    //where
    //    P1: AsRef<Path>,
    //{
    //    let root_path = root_path.as_ref().to_owned();
    //    let root_buf = std::fs::read(&root_path).context(error::FileRead { path: &root_path })?;
    //    let signed_root = serde_json::from_slice::<Signed<Root>>(&root_buf)
    //        .context(error::FileParseJson { path: &root_path })?;
    //    let root_digest = RootDigest::load(&root_path)?;
    //    let key_pairs = root_digest.load_keys(&keys)?;

    //    let rng = SystemRandom::new();

    //    let mut signed_targets = Signed {
    //        signed: self.targets.clone(),
    //        signatures: Vec::new(),
    //    };
    //    let (targets_sha256, targets_length) = RepositoryEditor::sign_role(
    //        datastore_path,
    //        &root_digest.root,
    //        &key_pairs,
    //        &mut signed_targets,
    //        self.targets.version,
    //        &rng,
    //        "targets.json",
    //    )?;

    //    // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=
    //    // Update and sign snapshot
    //    self.snapshot.meta = hashmap! {
    //        "root.json".to_owned() => SnapshotMeta {
    //            hashes: Some(Hashes {
    //                sha256: root_digest.digest.to_vec().into(),
    //                _extra: HashMap::new(),
    //            }),
    //            length: Some(root_digest.size),
    //            version: root_digest.root.version,
    //            _extra: HashMap::new(),
    //        },
    //        "targets.json".to_owned() => SnapshotMeta {
    //            hashes: Some(Hashes {
    //                sha256: targets_sha256.to_vec().into(),
    //                _extra: HashMap::new(),
    //            }),
    //            length: Some(targets_length),
    //            version: self.targets.version,
    //            _extra: HashMap::new(),
    //        },
    //    };
    //    let mut signed_snapshot = Signed {
    //        signed: self.snapshot.clone(),
    //        signatures: Vec::new(),
    //    };
    //    let (snapshot_sha256, snapshot_length) = RepositoryEditor::sign_role(
    //        datastore_path,
    //        &root_digest.root,
    //        &key_pairs,
    //        &mut signed_snapshot,
    //        self.snapshot.version,
    //        &rng,
    //        "snapshot.json",
    //    )?;

    //    // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=
    //    // Update and sign timestamp
    //    self.timestamp.meta = hashmap! {
    //        "snapshot.json".to_owned() => TimestampMeta {
    //            hashes: Hashes {
    //                sha256: snapshot_sha256.to_vec().into(),
    //                _extra: HashMap::new(),
    //            },
    //            length: snapshot_length,
    //            version: self.snapshot.version,
    //            _extra: HashMap::new(),
    //        }
    //    };
    //    let mut signed_timestamp = Signed {
    //        signed: self.timestamp.clone(),
    //        signatures: Vec::new(),
    //    };
    //    let (_timestamp_sha256, _timestamp_length) = RepositoryEditor::sign_role(
    //        datastore_path,
    //        &root_digest.root,
    //        &key_pairs,
    //        &mut signed_timestamp,
    //        self.timestamp.version,
    //        &rng,
    //        "timestamp.json",
    //    )?;

    //    let expires_iter = [
    //        (root_digest.root.expires, RoleType::Root),
    //        (self.timestamp.expires, RoleType::Timestamp),
    //        (self.snapshot.expires, RoleType::Snapshot),
    //        (self.targets.expires, RoleType::Targets),
    //    ];
    //    let (earliest_expiration, earliest_expiration_role) =
    //        expires_iter.iter().min_by_key(|tup| tup.0).unwrap();

    //    let datastore = Datastore::new(datastore_path);
    //    let transport = TargetMapTransport {
    //        targets: HashMap::new(),
    //    };

    //    let repo = Repository {
    //        transport: &transport,
    //        consistent_snapshot: true,
    //        datastore,
    //        earliest_expiration: earliest_expiration.to_owned(),
    //        earliest_expiration_role: *earliest_expiration_role,
    //        root: signed_root,
    //        snapshot: signed_snapshot,
    //        timestamp: signed_timestamp,
    //        targets: signed_targets,
    //        targets_base_url: Url::parse("target_map:///").context(error::ParseUrl {
    //            url: "target_map:///",
    //        })?,
    //    };
    //    Ok(repo)
    //}

    //fn sign_role<T, P>(
    //    outdir: P,
    //    root: &Root,
    //    keys: &RootKeys,
    //    role: &mut Signed<T>,
    //    version: NonZeroU64,
    //    rng: &dyn SecureRandom,
    //    filename: &'static str,
    //) -> Result<([u8; SHA256_OUTPUT_LEN], u64)>
    //where
    //    T: Role + Serialize,
    //    P: AsRef<Path>,
    //{
    //    let metadir = outdir.as_ref().join("metadata");
    //    std::fs::create_dir_all(&metadir).context(error::FileCreate { path: &metadir })?;

    //    let path = metadir.join(
    //        if T::TYPE != RoleType::Timestamp && root.consistent_snapshot {
    //            format!("{}.{}", version, filename)
    //        } else {
    //            filename.to_owned()
    //        },
    //    );

    //    let mut role = Signed {
    //        signed: role,
    //        signatures: Vec::new(),
    //    };

    //    let role_type = T::TYPE;
    //    if let Some(role_keys) = root.roles.get(&role_type) {
    //        for (keyid, key) in keys {
    //            if role_keys.keyids.contains(&keyid) {
    //                let mut data = Vec::new();
    //                let mut ser = serde_json::Serializer::with_formatter(
    //                    &mut data,
    //                    CanonicalFormatter::new(),
    //                );
    //                role.signed
    //                    .serialize(&mut ser)
    //                    .context(error::SerializeRole)?;
    //                let sig = key.sign(&data, rng)?;
    //                role.signatures.push(Signature {
    //                    keyid: keyid.clone(),
    //                    sig: sig.into(),
    //                });
    //            }
    //        }
    //    }

    //    let mut buf = serde_json::to_vec_pretty(&role).context(error::SerializeSignedRole)?;
    //    buf.push(b'\n');
    //    std::fs::write(&path, &buf).context(error::FileCreate { path: &path })?;

    //    let mut sha256 = [0; SHA256_OUTPUT_LEN];
    //    sha256.copy_from_slice(digest(&SHA256, &buf).as_ref());
    //    Ok((sha256, buf.len() as u64))
    //}
}
