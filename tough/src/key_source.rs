// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error;
use crate::sign::{parse_keypair, Sign};
use snafu::ResultExt;
use std::fmt::Debug;
use std::path::PathBuf;
use std::result::Result;

/// This trait should be implemented for each source of signing keys. Examples
/// of sources include: files, AWS SSM, etc.
pub trait KeySource: Debug + Send + Sync {
    /// Returns an object that implements the `Sign` trait
    fn as_sign(&self) -> Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// Writes a key back to the `KeySource`
    fn write(
        &self,
        value: &str,
        key_id_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
}

#[derive(Debug)]
pub struct LocalKeySource {
    pub path: PathBuf,
}

/// Implements the `KeySource` trait for a `LocalKeySource` (file)
impl KeySource for LocalKeySource {
    fn as_sign(&self) -> Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let data = std::fs::read(&self.path).context(error::FileRead { path: &self.path })?;
        Ok(Box::new(parse_keypair(&data)?))
    }

    fn write(
        &self,
        value: &str,
        _key_id_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(std::fs::write(&self.path, value.as_bytes())
            .context(error::FileWrite { path: &self.path })?)
    }
}
