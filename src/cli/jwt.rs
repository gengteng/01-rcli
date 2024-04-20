use crate::{process_jwt_sign, process_jwt_verify, CmdExector};
use chrono::{Duration, Utc};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use fancy_duration::FancyDuration;
use std::ops::Add;

/// Represents JWT-related subcommands that can be executed.
/// This enum uses command dispatch to delegate operations to specific subcommands.
#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JwtSubCommand {
    /// Generates a JWT based on the provided options.
    #[command()]
    Sign(JwtSignOpts),

    /// Verifies a JWT against the provided options.
    #[command()]
    Verify(JwtVerifyOpts),
}

/// Options for the 'Sign' subcommand to generate a JWT.
#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    /// Optional 'subject' claim to include in the JWT. Used to identify the principal that is the subject of the JWT.
    #[arg(short, long)]
    pub sub: Option<String>,

    /// Optional 'audience' claim to include in the JWT. Intended for the recipients that the JWT is issued for.
    #[arg(short, long)]
    pub aud: Option<String>,

    /// The 'expiration' time for the JWT. Specifies when the token will expire.
    #[arg(short, long)]
    pub exp: FancyDuration<Duration>,

    /// The secret key used for signing the JWT. This is a mandatory argument.
    #[arg(short, long)]
    pub key: String,
}

/// Options for the 'Verify' subcommand to check a JWT's validity.
#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    /// Optional 'subject' claim to verify in the JWT. Matches the principal that is the subject of the JWT.
    #[arg(short, long)]
    pub sub: Option<String>,

    /// Optional 'audience' claim to verify in the JWT. Should match the intended recipients of the JWT.
    #[arg(short, long)]
    pub aud: Option<String>,

    /// The JWT to be verified. This is a mandatory argument.
    #[arg(short, long)]
    pub token: String,

    /// The secret key used to verify the JWT. This is a mandatory argument.
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
