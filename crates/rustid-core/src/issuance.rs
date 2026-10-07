//! Serialising user tokens: user access tokens
//! as JWTs or reference tokens, identity tokens as JWTs. Shared by the token
//! endpoint (codes) and the authorize endpoint (implicit and hybrid).

use chrono::{DateTime, Utc};

use crate::clients::{AccessTokenType, Client};
use crate::jwt;
use crate::key_service::KeyService;
use crate::options::ProtocolOptions;
use crate::profile::{ProfileRequest, callers};
use crate::reference_tokens::{self, ReferenceToken};
use crate::scopes::ValidatedResources;
use crate::session::UserSession;
use crate::stores::Stores;
use crate::token::TokenFailure;
use crate::tokens::{
    AccessToken, Claim, IdentityTokenRequest, access_token_claim_types, identity_token,
    identity_token_claim_types, includes_identity_claims, jwt_payload, new_jwt_id,
    user_access_token,
};

/// A user access token before serialisation, and its `jti`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AccessTokenRecord {
    pub token: AccessToken,
    pub jti: Option<String>,
}

/// Where tokens are signed and stored, and on whose behalf.
pub struct Issuer<'a> {
    pub options: &'a ProtocolOptions,
    pub stores: &'a Stores,
    pub keys: &'a KeyService,
    pub issuer: &'a str,
    pub now: DateTime<Utc>,
}

impl Issuer<'_> {
    /// A user access token for the client's type: a JWT signed with a key
    /// every requested API allows, or a reference token recording the
    /// subject and session.
    pub async fn user_access_token(
        &self,
        client: &Client,
        resources: &ValidatedResources,
        session: &UserSession,
        session_id: Option<&str>,
        description: Option<&str>,
    ) -> Result<String, TokenFailure> {
        let record = self
            .user_access_token_record(client, resources, session, session_id)
            .await?;
        self.serialize_access_token(
            client,
            resources,
            &record,
            &session.subject_id,
            session_id,
            description,
        )
        .await
    }

    /// Create access token for a user: the token before it is
    /// serialised, with the `jti` it will carry. Refresh tokens keep it.
    pub async fn user_access_token_record(
        &self,
        client: &Client,
        resources: &ValidatedResources,
        session: &UserSession,
        session_id: Option<&str>,
    ) -> Result<AccessTokenRecord, TokenFailure> {
        let profile = self
            .profile_claims(
                callers::ACCESS_TOKEN,
                client,
                session,
                &access_token_claim_types(resources),
            )
            .await?;
        Ok(AccessTokenRecord {
            token: user_access_token(
                self.options,
                self.issuer,
                client,
                resources,
                session,
                session_id,
                profile,
            ),
            jti: client.include_jwt_id.then(new_jwt_id),
        })
    }

    /// The record as a JWT, or as a reference
    /// token stored for the subject and session, created now.
    pub async fn serialize_access_token(
        &self,
        client: &Client,
        resources: &ValidatedResources,
        record: &AccessTokenRecord,
        subject_id: &str,
        session_id: Option<&str>,
        description: Option<&str>,
    ) -> Result<String, TokenFailure> {
        // Computed for both token types: the request fails when the
        // APIs share no signing algorithm even if nothing is signed.
        let allowed = resources
            .allowed_signing_algorithms()
            .map_err(|e| TokenFailure::Server(e.to_string()))?;
        let token = &record.token;
        if client.access_token_type == AccessTokenType::Reference {
            let mut claims = token.claims.clone();
            if let Some(jti) = &record.jti {
                claims.push(Claim::string("jti", jti));
            }
            return Ok(reference_tokens::store(
                self.stores.grants.as_ref(),
                &ReferenceToken {
                    issuer: token.issuer.clone(),
                    client_id: token.client_id.clone(),
                    audiences: token.audiences.clone(),
                    creation_time: self.now,
                    lifetime: token.lifetime,
                    claims,
                    confirmation: token.confirmation.clone(),
                    subject_id: Some(subject_id.to_owned()),
                    session_id: session_id.map(str::to_owned),
                    description: description.map(str::to_owned),
                },
            )
            .await?);
        }
        self.sign_access_token(token, &allowed, record.jti.as_deref())
            .await
    }

    /// Get profile data for the session's subject.
    async fn profile_claims(
        &self,
        caller: &str,
        client: &Client,
        session: &UserSession,
        requested: &[String],
    ) -> Result<Vec<Claim>, TokenFailure> {
        self.stores
            .profile
            .profile_claims(&ProfileRequest {
                caller,
                client,
                subject_id: &session.subject_id,
                subject_claims: &session.claims,
                requested_claim_types: requested,
            })
            .await
            .map_err(|e| TokenFailure::Server(e.to_string()))
    }

    /// A JWT access token with the configured `typ`.
    pub async fn sign_access_token(
        &self,
        token: &AccessToken,
        allowed: &[String],
        jti: Option<&str>,
    ) -> Result<String, TokenFailure> {
        let key = self.keys.signing_key(allowed).await?.ok_or_else(|| {
            TokenFailure::Server(format!("no signing key for algorithms {allowed:?}"))
        })?;
        let payload = jwt_payload(self.options, token, self.now.timestamp(), jti)
            .map_err(|e| TokenFailure::Server(e.to_string()))?;
        let typ = self.options.access_token_jwt_type.as_str();
        let header: &[(&str, &str)] = if typ.is_empty() { &[] } else { &[("typ", typ)] };
        jwt::encode(&key, header, &payload).map_err(|e| TokenFailure::Server(e.to_string()))
    }

    /// The algorithm identity tokens for the client are signed with, which
    /// the hash claims (`at_hash`, `c_hash`, `s_hash`) follow.
    pub async fn identity_token_algorithm(&self, client: &Client) -> Result<String, TokenFailure> {
        let allowed = &client.allowed_identity_token_signing_algorithms;
        Ok(self
            .keys
            .signing_key(allowed)
            .await?
            .ok_or_else(|| TokenFailure::Server("No signing credential is configured.".into()))?
            .alg
            .clone())
    }

    /// An identity token (`typ: JWT`) signed with a key the client allows.
    pub async fn identity_token(
        &self,
        client: &Client,
        resources: &ValidatedResources,
        session: &UserSession,
        request: &IdentityTokenRequest<'_>,
    ) -> Result<String, TokenFailure> {
        let allowed = &client.allowed_identity_token_signing_algorithms;
        let key = self.keys.signing_key(allowed).await?.ok_or_else(|| {
            TokenFailure::Server(format!("no signing key for algorithms {allowed:?}"))
        })?;
        let profile = if includes_identity_claims(client, request) {
            self.profile_claims(
                callers::IDENTITY_TOKEN,
                client,
                session,
                &identity_token_claim_types(resources),
            )
            .await?
        } else {
            Vec::new()
        };
        let pairwise = crate::pairwise::subject(self.options, client, &session.subject_id);
        let request = IdentityTokenRequest {
            subject: pairwise.as_deref(),
            ..request.clone()
        };
        let token = identity_token(self.issuer, client, session, &request, &key.alg, profile);
        let payload = jwt_payload(self.options, &token, self.now.timestamp(), None)
            .map_err(|e| TokenFailure::Server(e.to_string()))?;
        jwt::encode(&key, &[("typ", "JWT")], &payload)
            .map_err(|e| TokenFailure::Server(e.to_string()))
    }
}
