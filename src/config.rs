use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;
use std::{env, fs};

#[derive(Deserialize)]
pub struct Server {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Deserialize)]
pub struct Database {
    pub url: String,
}

#[derive(Deserialize)]
pub struct Config {
    pub server: Server,
    pub database: Database,
}

pub fn load_config() -> Config {
    let path = PathBuf::from(env::args().nth(1).unwrap());
    let text = fs::read_to_string(&path).unwrap();
    toml::from_str(&text).unwrap()
}
