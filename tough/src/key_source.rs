// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::Result;
use crate::schema::key::Key;
use crate::sign::Sign;

/// This trait must be implemented for sources of keys. Examples
/// of sources are local files, AWS SSM, etc.
pub trait KeySource {
    /// Returns a type that implements the `Sign` trait
    fn as_sign(&self) -> Result<Box<dyn Sign>>;

    /// Returns a member of the `Key` enum
    fn as_public_key(&self) -> Result<Key>;
}
