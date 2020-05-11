use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use url::Url;

pub trait Transport {
    type Stream: Read;
    type Error: std::error::Error + Send + Sync + 'static;

    fn fetch(&self, url: Url) -> Result<Self::Stream, Self::Error>;
}

#[derive(Debug, Clone, Copy)]
pub struct FilesystemTransport;

impl Transport for FilesystemTransport {
    type Stream = std::fs::File;
    type Error = std::io::Error;

    fn fetch(&self, url: Url) -> Result<Self::Stream, Self::Error> {
        use std::io::{Error, ErrorKind};

        if url.scheme() == "file" {
            std::fs::File::open(url.path())
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!("unexpected URL scheme: {}", url.scheme()),
            ))
        }
    }
}

#[derive(Debug)]
pub(crate) struct TargetMapTransport {
    pub targets: HashMap<String, PathBuf>,
}

impl Transport for TargetMapTransport {
    type Stream = std::fs::File;
    type Error = std::io::Error;

    fn fetch(&self, url: Url) -> Result<Self::Stream, Self::Error> {
        use std::io::{Error, ErrorKind};

        if url.scheme() == "target-hashmap" {
            if let Some(target) = self.targets.get(url.path()) {
                std::fs::File::open(target)
            } else {
                Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unknown target path: {}", url.path()),
                ))
            }
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!("unexpected URL scheme: {}", url.scheme()),
            ))
        }
    }
}

#[cfg(feature = "http")]
pub type HttpTransport = reqwest::blocking::Client;

#[cfg(feature = "http")]
impl Transport for reqwest::blocking::Client {
    type Stream = reqwest::blocking::Response;
    type Error = reqwest::Error;

    fn fetch(&self, url: Url) -> Result<Self::Stream, Self::Error> {
        self.get(url.as_str()).send()?.error_for_status()
    }
}
