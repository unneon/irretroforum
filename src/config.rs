use knuffel::ast::{Literal, TypeName};
use knuffel::decode::{Context, Kind};
use knuffel::errors::{DecodeError, ExpectedType};
use knuffel::span::Spanned;
use knuffel::traits::ErrorSpan;
use knuffel::{Decode, DecodeScalar};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Decode, Serialize)]
pub struct Site {
    #[knuffel(child, unwrap(argument))]
    pub name: String,
}

pub struct IpAddrWrapper(pub IpAddr);

#[derive(Decode)]
pub struct Server {
    #[knuffel(child, unwrap(argument))]
    pub address: IpAddrWrapper,
    #[knuffel(child, unwrap(argument))]
    pub port: u16,
}

#[derive(Decode)]
pub struct Database {
    #[knuffel(child, unwrap(argument))]
    pub url: String,
}

#[derive(Decode)]
pub struct Config {
    #[knuffel(child)]
    pub site: Site,
    #[knuffel(child)]
    pub server: Server,
    #[knuffel(child)]
    pub database: Database,
}

impl<S: ErrorSpan> DecodeScalar<S> for IpAddrWrapper {
    fn type_check(type_name: &Option<Spanned<TypeName, S>>, ctx: &mut Context<S>) {
        if let Some(typ) = type_name {
            ctx.emit_error(DecodeError::TypeName {
                span: typ.span().clone(),
                found: Some((**typ).clone()),
                expected: ExpectedType::no_type(),
                rust_type: "IpAddr",
            });
        }
    }

    fn raw_decode(
        value: &Spanned<Literal, S>,
        ctx: &mut Context<S>,
    ) -> Result<Self, DecodeError<S>> {
        match &**value {
            Literal::String(s) => match IpAddr::from_str(s) {
                Ok(ip) => return Ok(IpAddrWrapper(ip)),
                Err(e) => ctx.emit_error(DecodeError::conversion(value, e)),
            },
            _ => ctx.emit_error(DecodeError::scalar_kind(Kind::String, value)),
        }
        Ok(IpAddrWrapper(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
    }
}

pub fn load_config() -> Config {
    let path = PathBuf::from(std::env::args().nth(1).unwrap());
    let text = std::fs::read_to_string(&path).unwrap();
    knuffel::parse(path.to_str().unwrap(), &text).unwrap()
}
