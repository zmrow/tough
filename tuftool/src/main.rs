// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

#![deny(rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    // Identifiers like Command::Create are clearer than Self::Create regardless of context
    clippy::use_self,
    // Caused by interacting with tough::schema::*._extra
    clippy::used_underscore_binding,
)]

mod create;
mod datetime;
mod download;
mod error;
mod key;
mod metadata;
mod refresh;
mod root;
mod root_digest;
mod sign;
mod source;

use crate::error::Result;
use snafu::{ErrorCompat, OptionExt, ResultExt};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use structopt::StructOpt;
use tempfile::NamedTempFile;

static SPEC_VERSION: &str = "1.0.0";

#[derive(Debug, StructOpt)]
enum Command {
    /// Create a TUF repository
    Create(create::CreateArgs),
    /// Manipulate a root.json metadata file
    Root(root::Command),
    /// Sign a metadata file
    Sign(sign::SignArgs),
    /// Refresh metadata files
    Refresh(refresh::RefreshArgs),
    /// Download a TUF repository's resources
    Download(download::DownloadArgs),
}

impl Command {
    fn run(&self) -> Result<()> {
        match self {
            Command::Create(args) => args.run(),
            Command::Root(root_subcommand) => root_subcommand.run(),
            Command::Sign(args) => args.run(),
            Command::Refresh(args) => args.run(),
            Command::Download(args) => args.run(),
        }
    }
}

fn load_file<T>(path: &Path) -> Result<T>
where
    for<'de> T: serde::Deserialize<'de>,
{
    serde_json::from_reader(File::open(path).context(error::FileOpen { path })?)
        .context(error::FileParseJson { path })
}

fn write_file<T>(path: &Path, json: &T) -> Result<()>
where
    T: serde::Serialize,
{
    // Use `tempfile::NamedTempFile::persist` to perform an atomic file write.
    let parent = path.parent().context(error::PathParent { path })?;
    let mut writer =
        NamedTempFile::new_in(parent).context(error::FileTempCreate { path: parent })?;
    serde_json::to_writer_pretty(&mut writer, json).context(error::FileWriteJson { path })?;
    writer.write_all(b"\n").context(error::FileWrite { path })?;
    writer.persist(path).context(error::FilePersist { path })?;
    Ok(())
}

fn main() -> ! {
    std::process::exit(match Command::from_args().run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{}", err);
            if let Some(var) = std::env::var_os("RUST_BACKTRACE") {
                if var != "0" {
                    if let Some(backtrace) = err.backtrace() {
                        eprintln!("\n{:?}", backtrace);
                    }
                }
            }
            1
        }
    })
}
