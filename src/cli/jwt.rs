use crate::{process_jwt_sign, process_jwt_verify, CmdExector};
use chrono::{Duration, Utc};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use fancy_duration::FancyDuration;
use std::ops::Add;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JwtSubCommand {
    #[command(about = "Generate a JWT")]
    Sign(JwtSignOpts),
    #[command(about = "Verify a JWT")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(short, long)]
    pub sub: Option<String>,
    #[arg(short, long)]
    pub aud: Option<String>,
    #[arg(short, long)]
    pub exp: FancyDuration<Duration>,
    #[arg(short, long)]
    pub key: String,
}

impl CmdExector for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let JwtSignOpts { sub, aud, exp, key } = self;
        let exp = Utc::now().add(exp.0).timestamp() as usize;
        let jwt = process_jwt_sign(sub, aud, exp, &key)?;
        println!("{}", jwt);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long)]
    pub sub: Option<String>,
    #[arg(short, long)]
    pub aud: Option<String>,
    #[arg(short, long)]
    pub token: String,
    #[arg(short, long)]
    pub key: String,
}

impl CmdExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let JwtVerifyOpts {
            token,
            key,
            sub,
            aud,
        } = self;

        if let Some(error) = process_jwt_verify(sub, aud, &token, &key)? {
            println!("⚠ JWT not verified: {error}");
        } else {
            println!("✓ JWT verified");
        }

        Ok(())
    }
}
