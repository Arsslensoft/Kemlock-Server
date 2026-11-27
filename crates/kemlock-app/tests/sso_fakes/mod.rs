//! In-memory fakes of the SSO ports: repositories, a scripted OpenID Connect provider, a DNS
//! lookup, and the two space ports. Self-contained (it depends on nothing in `fakes/`), so the
//! API tests can include it too with `#[path]`.
#![allow(dead_code, unused_imports)]

use kemlock_app::ports::StoreError;
use kemlock_app::sso::model::{AuthorizationRequest, CodeExchange};
use kemlock_app::sso::ports::{
    GroupSync, MembershipFacts, OidcProvider, SpaceMembership, SsoIdentityRepo, SsoSettingsRepo,
    TxtLookup, VerifiedDomainRepo,
};
use kemlock_app::sso::{
    ClientConfig, GroupAssignment, IdentityClaims, LogoutClaims, SsoError, SsoIdentity, SsoSession,
    SsoSettings, VerifiedDomain,
};
use kemlock_domain::UserId;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------------------------
// Repositories.

#[derive(Default)]
struct ReposInner {
    settings: Option<SsoSettings>,
    identities: Vec<SsoIdentity>,
    domains: HashMap<String, VerifiedDomain>,
    sessions: Vec<SsoSession>,
}

#[derive(Clone, Default)]
pub(crate) struct FakeSsoRepos(Arc<Mutex<ReposInner>>);

impl FakeSsoRepos {
    fn lock(&self) -> MutexGuard<'_, ReposInner> {
        self.0.lock().expect("the repos lock isn't poisoned")
    }

    pub(crate) fn set_settings(&self, settings: SsoSettings) {
        self.lock().settings = Some(settings);
    }

    pub(crate) fn settings(&self) -> Option<SsoSettings> {
        self.lock().settings.clone()
    }

    /// Takes in sessions another port recorded: the SQL store keeps one table for both, the fakes
    /// keep two.
    pub(crate) fn adopt_sessions(&self, sessions: Vec<SsoSession>) {
        for session in sessions {
            let mut g = self.lock();
            g.sessions.retain(|s| s.device != session.device);
            g.sessions.push(session);
        }
    }

    pub(crate) fn sessions(&self) -> Vec<SsoSession> {
        self.lock().sessions.clone()
    }

    pub(crate) fn identities(&self) -> Vec<SsoIdentity> {
        self.lock().identities.clone()
    }

    pub(crate) fn add_verified_domain(&self, domain: &str, at: OffsetDateTime) {
        self.lock().domains.insert(
            domain.to_owned(),
            VerifiedDomain {
                domain: domain.to_owned(),
                token: "already-proven".to_owned(),
                created_at: at,
                verified_at: Some(at),
            },
        );
    }
}

impl SsoSettingsRepo for FakeSsoRepos {
    async fn sso_settings(&self) -> Result<Option<SsoSettings>, StoreError> {
        Ok(self.settings())
    }

    async fn put_sso_settings(&self, settings: &SsoSettings) -> Result<(), StoreError> {
        self.lock().settings = Some(settings.clone());
        Ok(())
    }
}

impl SsoIdentityRepo for FakeSsoRepos {
    async fn find_identity(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<SsoIdentity>, StoreError> {
        Ok(self
            .lock()
            .identities
            .iter()
            .find(|i| i.issuer == issuer && i.subject == subject)
            .cloned())
    }

    async fn insert_identity(&self, identity: &SsoIdentity) -> Result<(), StoreError> {
        let mut g = self.lock();
        if g.identities
            .iter()
            .any(|i| i.issuer == identity.issuer && i.subject == identity.subject)
        {
            return Err(StoreError::Duplicate);
        }
        g.identities.push(identity.clone());
        Ok(())
    }

    async fn identities_of(&self, user: UserId) -> Result<Vec<SsoIdentity>, StoreError> {
        Ok(self
            .lock()
            .identities
            .iter()
            .filter(|i| i.user == user)
            .cloned()
            .collect())
    }

    async fn touch_identity(
        &self,
        issuer: &str,
        subject: &str,
        email: &str,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let mut g = self.lock();
        match g
            .identities
            .iter_mut()
            .find(|i| i.issuer == issuer && i.subject == subject)
        {
            Some(identity) => {
                identity.email = email.to_owned();
                identity.last_login_at = at;
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn record_sso_session(&self, session: &SsoSession) -> Result<(), StoreError> {
        let mut g = self.lock();
        g.sessions.retain(|s| s.device != session.device);
        g.sessions.push(session.clone());
        Ok(())
    }

    async fn sso_sessions(
        &self,
        issuer: &str,
        subject: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<Vec<SsoSession>, StoreError> {
        if subject.is_none() && session_id.is_none() {
            return Ok(Vec::new());
        }
        Ok(self
            .lock()
            .sessions
            .iter()
            .filter(|s| s.issuer == issuer)
            .filter(|s| subject.is_none_or(|v| s.subject == v))
            .filter(|s| {
                session_id.is_none_or(|v| {
                    s.session_id.as_deref() == Some(v)
                        || (subject.is_some() && s.session_id.is_none())
                })
            })
            .cloned()
            .collect())
    }
}

impl VerifiedDomainRepo for FakeSsoRepos {
    async fn domain_claim(&self, domain: &str) -> Result<Option<VerifiedDomain>, StoreError> {
        Ok(self.lock().domains.get(domain).cloned())
    }

    async fn domain_claims(&self) -> Result<Vec<VerifiedDomain>, StoreError> {
        let mut all: Vec<VerifiedDomain> = self.lock().domains.values().cloned().collect();
        all.sort_by(|a, b| a.domain.cmp(&b.domain));
        Ok(all)
    }

    async fn put_domain_claim(&self, claim: &VerifiedDomain) -> Result<(), StoreError> {
        self.lock()
            .domains
            .insert(claim.domain.clone(), claim.clone());
        Ok(())
    }

    async fn remove_domain_claim(&self, domain: &str) -> Result<(), StoreError> {
        self.lock().domains.remove(domain);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// The provider.

struct ProviderInner {
    claims: IdentityClaims,
    logout: Result<LogoutClaims, SsoError>,
    last_request: Option<AuthorizationRequest>,
    last_client: Option<ClientConfig>,
    spent_codes: HashSet<String>,
    exchanges: usize,
}

/// A provider that says whatever the test scripted, and checks that the server threads the nonce
/// and PKCE verifier from the authorization request into the code exchange.
#[derive(Clone)]
pub(crate) struct ScriptedProvider(Arc<Mutex<ProviderInner>>);

pub(crate) const ISSUER: &str = "https://idp.test";

pub(crate) fn claims(subject: &str, email: &str) -> IdentityClaims {
    IdentityClaims {
        issuer: ISSUER.to_owned(),
        subject: subject.to_owned(),
        email: Some(email.to_owned()),
        email_verified: Some(true),
        name: Some("Ada Lovelace".to_owned()),
        amr: Vec::new(),
        groups: Vec::new(),
        session_id: Some("provider-session-1".to_owned()),
    }
}

impl ScriptedProvider {
    pub(crate) fn new() -> Self {
        ScriptedProvider(Arc::new(Mutex::new(ProviderInner {
            claims: claims("sub-1", "ada@example.org"),
            logout: Ok(LogoutClaims {
                issuer: ISSUER.to_owned(),
                subject: Some("sub-1".to_owned()),
                session_id: None,
            }),
            last_request: None,
            last_client: None,
            spent_codes: HashSet::new(),
            exchanges: 0,
        })))
    }

    fn lock(&self) -> MutexGuard<'_, ProviderInner> {
        self.0.lock().expect("the provider lock isn't poisoned")
    }

    pub(crate) fn say(&self, claims: IdentityClaims) {
        self.lock().claims = claims;
    }

    pub(crate) fn say_logout(&self, logout: Result<LogoutClaims, SsoError>) {
        self.lock().logout = logout;
    }

    pub(crate) fn last_request(&self) -> Option<AuthorizationRequest> {
        self.lock().last_request.clone()
    }

    pub(crate) fn last_client(&self) -> Option<ClientConfig> {
        self.lock().last_client.clone()
    }

    pub(crate) fn exchanges(&self) -> usize {
        self.lock().exchanges
    }
}

impl OidcProvider for ScriptedProvider {
    async fn authorization_url(
        &self,
        client: &ClientConfig,
        request: &AuthorizationRequest,
    ) -> Result<String, SsoError> {
        let mut g = self.lock();
        g.last_client = Some(client.clone());
        g.last_request = Some(request.clone());
        Ok(format!(
            "{}/authorize?client_id={}&state={}&nonce={}&redirect_uri={}",
            client.issuer, client.client_id, request.state, request.nonce, request.redirect_uri
        ))
    }

    async fn exchange(
        &self,
        client: &ClientConfig,
        request: &CodeExchange,
    ) -> Result<IdentityClaims, SsoError> {
        let mut g = self.lock();
        g.exchanges += 1;
        g.last_client = Some(client.clone());
        // A provider's code works once.
        if !g.spent_codes.insert(request.code.clone()) {
            return Err(SsoError::Provider("invalid_grant".to_owned()));
        }
        let Some(asked) = g.last_request.clone() else {
            return Err(SsoError::Provider("no authorization request".to_owned()));
        };
        if asked.nonce != request.nonce {
            return Err(SsoError::Token("nonce mismatch".to_owned()));
        }
        if asked.code_verifier != request.code_verifier {
            return Err(SsoError::Provider("PKCE verifier mismatch".to_owned()));
        }
        if asked.redirect_uri != request.redirect_uri {
            return Err(SsoError::Provider("redirect_uri mismatch".to_owned()));
        }
        Ok(g.claims.clone())
    }

    async fn validate_logout_token(
        &self,
        _client: &ClientConfig,
        _token: &str,
    ) -> Result<LogoutClaims, SsoError> {
        self.lock().logout.clone()
    }
}

// ---------------------------------------------------------------------------------------------
// DNS, and the space ports.

#[derive(Clone, Default)]
pub(crate) struct FakeDns(Arc<Mutex<HashMap<String, Vec<String>>>>);

impl FakeDns {
    pub(crate) fn publish(&self, name: &str, record: &str) {
        self.0
            .lock()
            .expect("the dns lock isn't poisoned")
            .entry(name.to_owned())
            .or_default()
            .push(record.to_owned());
    }
}

impl TxtLookup for FakeDns {
    async fn txt_records(&self, name: &str) -> Result<Vec<String>, SsoError> {
        Ok(self
            .0
            .lock()
            .expect("the dns lock isn't poisoned")
            .get(name)
            .cloned()
            .unwrap_or_default())
    }
}

#[derive(Clone, Default)]
pub(crate) struct FakeMembership(Arc<Mutex<HashMap<UserId, Vec<SpaceMembership>>>>);

impl FakeMembership {
    pub(crate) fn put(&self, user: UserId, spaces: Vec<SpaceMembership>) {
        self.0
            .lock()
            .expect("the membership lock isn't poisoned")
            .insert(user, spaces);
    }
}

impl MembershipFacts for FakeMembership {
    async fn spaces_of(&self, user: UserId) -> Result<Vec<SpaceMembership>, StoreError> {
        Ok(self
            .0
            .lock()
            .expect("the membership lock isn't poisoned")
            .get(&user)
            .cloned()
            .unwrap_or_default())
    }
}

#[derive(Default)]
struct GroupsInner {
    calls: Vec<(UserId, Vec<GroupAssignment>)>,
    fail: bool,
}

#[derive(Clone, Default)]
pub(crate) struct RecordingGroups(Arc<Mutex<GroupsInner>>);

impl RecordingGroups {
    pub(crate) fn failing() -> Self {
        let groups = RecordingGroups::default();
        groups
            .0
            .lock()
            .expect("the groups lock isn't poisoned")
            .fail = true;
        groups
    }

    pub(crate) fn calls(&self) -> Vec<(UserId, Vec<GroupAssignment>)> {
        self.0
            .lock()
            .expect("the groups lock isn't poisoned")
            .calls
            .clone()
    }
}

impl GroupSync for RecordingGroups {
    async fn apply_groups(
        &self,
        user: UserId,
        assignments: &[GroupAssignment],
    ) -> Result<(), StoreError> {
        let mut g = self.0.lock().expect("the groups lock isn't poisoned");
        g.calls.push((user, assignments.to_vec()));
        if g.fail {
            Err(StoreError::Backend("spaces are down".to_owned()))
        } else {
            Ok(())
        }
    }
}
