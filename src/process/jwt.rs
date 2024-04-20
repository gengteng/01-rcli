use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: Option<String>,
    aud: Option<String>,
    exp: usize,
}

pub fn process_jwt_sign(
    sub: impl Into<Option<String>>,
    aud: impl Into<Option<String>>,
    exp: usize,
    key: &str,
) -> anyhow::Result<String> {
    let claims = Claims {
        sub: sub.into(),
        aud: aud.into(),
        exp,
    };
    Ok(jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_base64_secret(key)?,
    )?)
}

pub fn process_jwt_verify(
    sub: impl Into<Option<String>>,
    aud: impl Into<Option<String>>,
    token: &str,
    key: &str,
) -> anyhow::Result<Option<jsonwebtoken::errors::Error>> {
    let decoding_key = DecodingKey::from_base64_secret(key)?;
    let validation = {
        let mut v = Validation::default();
        v.sub = sub.into();
        v.validate_aud = if let Some(aud) = aud.into() {
            v.aud = Some({
                let mut set = HashSet::new();
                set.insert(aud);
                set
            });
            true
        } else {
            false
        };
        v
    };
    Ok(jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).err())
}
