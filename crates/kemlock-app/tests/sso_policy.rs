//! The Require SSO check other sign-in paths call, and the DNS domain proof.

mod fakes;
mod sso_fakes;

use fakes::*;
use kemlock_app::AppError;
use kemlock_app::sso::{
    DomainProofs, Rechecked, RequireSso, SignInMethod, SpaceMembership, SpaceRole, SsoError,
};
use kemlock_domain::{Role, SpaceId, User};
use sso_fakes::*;

async fn member_user(world: &World, email: &str) -> User {
    let id = make_user(world, email).await;
    world.store.user(id).expect("the account exists")
}

fn policy(membership: &FakeMembership) -> RequireSso<FakeMembership> {
    RequireSso {
        membership: membership.clone(),
    }
}

const BLOCKED: [SignInMethod; 3] = [
    SignInMethod::Password,
    SignInMethod::Passkey,
    SignInMethod::PhoneApproval,
];

#[tokio::test]
async fn a_member_of_a_requiring_space_is_blocked_from_every_way_but_sso() {
    let world = World::new().with_signups();
    let user = member_user(&world, "sam@example.org").await;
    let membership = FakeMembership::default();
    let space = SpaceId::random();
    membership.put(
        user.id,
        vec![SpaceMembership {
            space,
            role: SpaceRole::Member,
            require_sso: true,
        }],
    );

    for method in BLOCKED {
        assert_eq!(
            policy(&membership).check(&user, method).await,
            Err(SsoError::SsoRequired { space }),
            "{method:?}"
        );
    }
    assert_eq!(
        policy(&membership).check(&user, SignInMethod::Sso).await,
        Ok(())
    );
}

#[tokio::test]
async fn the_error_names_the_space_for_other_sign_in_paths() {
    let world = World::new().with_signups();
    let user = member_user(&world, "sam@example.org").await;
    let membership = FakeMembership::default();
    let space = SpaceId::random();
    membership.put(
        user.id,
        vec![SpaceMembership {
            space,
            role: SpaceRole::Member,
            require_sso: true,
        }],
    );
    let error = policy(&membership)
        .check(&user, SignInMethod::Password)
        .await
        .expect_err("blocked");
    assert_eq!(AppError::from(error), AppError::SsoRequired { space });
}

#[tokio::test]
async fn owners_admins_and_server_admins_are_exempt() {
    let world = World::new().with_signups();
    let user = member_user(&world, "sam@example.org").await;
    let membership = FakeMembership::default();

    for role in [SpaceRole::Owner, SpaceRole::Admin] {
        membership.put(
            user.id,
            vec![SpaceMembership {
                space: SpaceId::random(),
                role,
                require_sso: true,
            }],
        );
        for method in BLOCKED {
            assert_eq!(
                policy(&membership).check(&user, method).await,
                Ok(()),
                "{role:?} {method:?}"
            );
        }
    }

    // A server admin who is only an ordinary member of the space is exempt too, so the person
    // who can fix the provider can always get in.
    membership.put(
        user.id,
        vec![SpaceMembership {
            space: SpaceId::random(),
            role: SpaceRole::Member,
            require_sso: true,
        }],
    );
    let admin = User {
        role: Role::Admin,
        ..user
    };
    assert_eq!(
        policy(&membership)
            .check(&admin, SignInMethod::Password)
            .await,
        Ok(())
    );
}

#[tokio::test]
async fn accounts_in_no_space_or_a_space_without_the_policy_are_not_blocked() {
    let world = World::new().with_signups();
    let user = member_user(&world, "sam@example.org").await;
    let membership = FakeMembership::default();
    for method in BLOCKED {
        assert_eq!(policy(&membership).check(&user, method).await, Ok(()));
    }
    membership.put(
        user.id,
        vec![SpaceMembership {
            space: SpaceId::random(),
            role: SpaceRole::Member,
            require_sso: false,
        }],
    );
    for method in BLOCKED {
        assert_eq!(policy(&membership).check(&user, method).await, Ok(()));
    }
}

// ---------------------------------------------------------------------------------------------
// DNS proof of a domain

fn proofs(
    world: &World,
    repos: &FakeSsoRepos,
    dns: &FakeDns,
) -> DomainProofs<FakeSsoRepos, FakeDns, FakeEnv> {
    DomainProofs {
        repos: repos.clone(),
        dns: dns.clone(),
        env: world.env.clone(),
    }
}

#[tokio::test]
async fn claiming_a_domain_makes_a_token_and_asking_again_shows_the_same_one() {
    let world = World::new();
    let (repos, dns) = (FakeSsoRepos::default(), FakeDns::default());
    let first = proofs(&world, &repos, &dns)
        .begin("Example.ORG.")
        .await
        .expect("claims");
    assert_eq!(first.domain, "example.org");
    assert_eq!(first.token.len(), 32);
    assert!(first.token.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!first.is_verified());
    assert_eq!(
        first.txt_value(),
        format!("kemlock-verification={}", first.token)
    );

    let again = proofs(&world, &repos, &dns)
        .begin("example.org")
        .await
        .expect("claims again");
    assert_eq!(again, first);

    let other = proofs(&world, &repos, &dns)
        .begin("example.com")
        .await
        .expect("another domain");
    assert_ne!(other.token, first.token);
}

#[tokio::test]
async fn the_record_in_dns_verifies_the_domain() {
    let world = World::new();
    let (repos, dns) = (FakeSsoRepos::default(), FakeDns::default());
    let claim = proofs(&world, &repos, &dns)
        .begin("example.org")
        .await
        .expect("claims");

    // Not published yet.
    assert_eq!(
        proofs(&world, &repos, &dns).check("example.org").await,
        Err(SsoError::DomainProofMissing)
    );
    assert!(
        !proofs(&world, &repos, &dns)
            .is_verified("example.org")
            .await
            .expect("asks")
    );

    // A record with someone else's token doesn't prove it.
    dns.publish("example.org", "kemlock-verification=0000");
    dns.publish("example.org", "v=spf1 -all");
    assert_eq!(
        proofs(&world, &repos, &dns).check("example.org").await,
        Err(SsoError::DomainProofMissing)
    );

    // The right record, among others, does.
    dns.publish("example.org", &claim.txt_value());
    let verified = proofs(&world, &repos, &dns)
        .check("example.org")
        .await
        .expect("verified");
    assert!(verified.is_verified());
    assert_eq!(
        verified.verified_at,
        Some(kemlock_app::ports::Clock::now(&world.env))
    );
    assert!(
        proofs(&world, &repos, &dns)
            .is_verified("EXAMPLE.org")
            .await
            .expect("asks")
    );

    // Checking again doesn't need DNS: a verified claim stays.
    let dns_gone = FakeDns::default();
    let still = proofs(&world, &repos, &dns_gone)
        .check("example.org")
        .await
        .expect("still verified");
    assert_eq!(still, verified);
}

#[tokio::test]
async fn a_verified_domain_is_looked_at_again_after_a_while() {
    let world = World::new();
    let (repos, dns) = (FakeSsoRepos::default(), FakeDns::default());
    let week = time::Duration::days(7);
    let kept = proofs(&world, &repos, &dns)
        .begin("kept.example.org")
        .await
        .expect("claims");
    let lost = proofs(&world, &repos, &dns)
        .begin("lost.example.org")
        .await
        .expect("claims");
    let pending = proofs(&world, &repos, &dns)
        .begin("pending.example.org")
        .await
        .expect("claims");
    dns.publish("kept.example.org", &kept.txt_value());
    dns.publish("lost.example.org", &lost.txt_value());
    for domain in ["kept.example.org", "lost.example.org"] {
        proofs(&world, &repos, &dns)
            .check(domain)
            .await
            .expect("verified");
    }

    // Too soon: nothing is looked at, whatever DNS says now.
    world.env.clock.advance(time::Duration::days(6));
    let none_yet = FakeDns::default();
    assert_eq!(
        proofs(&world, &repos, &none_yet).recheck_stale(week).await,
        Ok(Rechecked::default())
    );
    assert!(
        proofs(&world, &repos, &none_yet)
            .is_verified("lost.example.org")
            .await
            .expect("asks")
    );

    // A week on, the record of one is still published and the other's is gone.
    world.env.clock.advance(time::Duration::days(1));
    let later = FakeDns::default();
    later.publish("kept.example.org", &kept.txt_value());
    assert_eq!(
        proofs(&world, &repos, &later).recheck_stale(week).await,
        Ok(Rechecked {
            kept: 1,
            dropped: 1,
            unreachable: 0
        })
    );
    let check = proofs(&world, &repos, &later);
    assert!(check.is_verified("kept.example.org").await.expect("asks"));
    assert!(!check.is_verified("lost.example.org").await.expect("asks"));
    assert!(!check.is_verified(&pending.domain).await.expect("asks"));
    // The one that held is verified afresh, so it is looked at again a week later, not at once.
    assert_eq!(
        proofs(&world, &repos, &FakeDns::default())
            .recheck_stale(week)
            .await,
        Ok(Rechecked::default())
    );
}

#[tokio::test]
async fn the_proof_is_looked_up_at_the_domain_itself() {
    let world = World::new();
    let (repos, dns) = (FakeSsoRepos::default(), FakeDns::default());
    let claim = proofs(&world, &repos, &dns)
        .begin("example.org")
        .await
        .expect("claims");
    dns.publish("sub.example.org", &claim.txt_value());
    dns.publish("example.net", &claim.txt_value());
    assert_eq!(
        proofs(&world, &repos, &dns).check("example.org").await,
        Err(SsoError::DomainProofMissing)
    );
}

#[tokio::test]
async fn checking_an_unclaimed_domain_or_a_bad_name_is_refused() {
    let world = World::new();
    let (repos, dns) = (FakeSsoRepos::default(), FakeDns::default());
    assert_eq!(
        proofs(&world, &repos, &dns).check("example.org").await,
        Err(SsoError::App(AppError::NotFound))
    );
    assert!(matches!(
        proofs(&world, &repos, &dns).begin("not a domain").await,
        Err(SsoError::Invalid(_))
    ));
    assert!(matches!(
        proofs(&world, &repos, &dns).check("localhost").await,
        Err(SsoError::Invalid(_))
    ));
}

#[tokio::test]
async fn removing_a_claim_forgets_it() {
    let world = World::new();
    let (repos, dns) = (FakeSsoRepos::default(), FakeDns::default());
    proofs(&world, &repos, &dns)
        .begin("example.org")
        .await
        .expect("claims");
    proofs(&world, &repos, &dns)
        .remove("example.org")
        .await
        .expect("removes");
    assert!(
        !proofs(&world, &repos, &dns)
            .is_verified("example.org")
            .await
            .expect("asks")
    );
    assert_eq!(
        proofs(&world, &repos, &dns).check("example.org").await,
        Err(SsoError::App(AppError::NotFound))
    );
}
