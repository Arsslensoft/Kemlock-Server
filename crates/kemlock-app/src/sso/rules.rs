//! The groups claim to space and role mapping. The admin's rules are data (a JSON list kept in
//! `sso_settings`); at each sign-in `map_groups` turns the groups the ID token names into the
//! assignments the spaces area applies.

use crate::sso::model::{GroupAssignment, GroupRule};
use uuid::Uuid;

/// The most rules one provider connection keeps, so a settings row stays small.
pub const MAX_RULES: usize = 500;

/// What the rules give someone in `groups`: one assignment per space, the highest role any
/// matching rule grants there, and the union of those rules' collections. Spaces come out in the
/// order their first matching rule appears; collections keep their first-seen order.
pub fn map_groups(rules: &[GroupRule], groups: &[String]) -> Vec<GroupAssignment> {
    let mut out: Vec<GroupAssignment> = Vec::new();
    for rule in rules {
        if !groups.iter().any(|g| g == &rule.group) {
            continue;
        }
        match out.iter_mut().find(|a| a.space == rule.space) {
            Some(existing) => {
                existing.role = existing.role.max(rule.role);
                merge_collections(&mut existing.collections, &rule.collections);
            }
            None => {
                let mut collections = Vec::new();
                merge_collections(&mut collections, &rule.collections);
                out.push(GroupAssignment {
                    space: rule.space,
                    role: rule.role,
                    collections,
                });
            }
        }
    }
    out
}

fn merge_collections(into: &mut Vec<Uuid>, more: &[Uuid]) {
    for id in more {
        if !into.contains(id) {
            into.push(*id);
        }
    }
}

/// The rules as the JSON a settings row keeps.
pub fn rules_to_json(rules: &[GroupRule]) -> String {
    // A list of plain structs always serialises; the fallback only keeps the signature total.
    serde_json::to_string(rules).unwrap_or_else(|_| "[]".to_owned())
}

/// The rules from a settings row. An empty string is no rules; anything else must parse, and
/// hold at most [`MAX_RULES`].
pub fn rules_from_json(json: &str) -> Result<Vec<GroupRule>, String> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let rules: Vec<GroupRule> =
        serde_json::from_str(json).map_err(|e| format!("group rules aren't valid: {e}"))?;
    if rules.len() > MAX_RULES {
        return Err(format!("there are more than {MAX_RULES} group rules"));
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sso::model::SpaceRole;
    use kemlock_domain::SpaceId;

    fn rule(group: &str, space: SpaceId, role: SpaceRole, collections: &[Uuid]) -> GroupRule {
        GroupRule {
            group: group.to_owned(),
            space,
            role,
            collections: collections.to_vec(),
        }
    }

    fn groups(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn no_matching_group_gives_nothing() {
        let space = SpaceId::random();
        let rules = vec![rule("eng", space, SpaceRole::Member, &[])];
        assert!(map_groups(&rules, &groups(&["sales"])).is_empty());
        assert!(map_groups(&rules, &[]).is_empty());
        assert!(map_groups(&[], &groups(&["eng"])).is_empty());
    }

    #[test]
    fn a_matching_group_grants_its_role_and_collections() {
        let space = SpaceId::random();
        let c = Uuid::from_u128(1);
        let rules = vec![rule("eng", space, SpaceRole::Admin, &[c])];
        assert_eq!(
            map_groups(&rules, &groups(&["eng", "other"])),
            vec![GroupAssignment {
                space,
                role: SpaceRole::Admin,
                collections: vec![c]
            }]
        );
    }

    #[test]
    fn groups_match_exactly() {
        let rules = vec![rule("eng", SpaceId::random(), SpaceRole::Member, &[])];
        assert!(map_groups(&rules, &groups(&["Eng", "eng ", "/eng"])).is_empty());
    }

    #[test]
    fn two_rules_for_one_space_merge_to_the_higher_role_and_all_collections() {
        let space = SpaceId::random();
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let rules = vec![
            rule("eng", space, SpaceRole::Member, &[a]),
            rule("leads", space, SpaceRole::Owner, &[a, b]),
            rule("ops", space, SpaceRole::Admin, &[b]),
        ];
        let out = map_groups(&rules, &groups(&["ops", "leads", "eng"]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].role, SpaceRole::Owner);
        assert_eq!(out[0].collections, vec![a, b]);
    }

    #[test]
    fn different_spaces_stay_apart_in_rule_order() {
        let (s1, s2) = (SpaceId::random(), SpaceId::random());
        let rules = vec![
            rule("b", s2, SpaceRole::Member, &[]),
            rule("a", s1, SpaceRole::Admin, &[]),
        ];
        let out = map_groups(&rules, &groups(&["a", "b"]));
        assert_eq!(
            out.iter().map(|x| x.space).collect::<Vec<_>>(),
            vec![s2, s1]
        );
    }

    #[test]
    fn rules_round_trip_through_json() {
        let rules = vec![rule(
            "eng",
            SpaceId::random(),
            SpaceRole::Owner,
            &[Uuid::from_u128(7)],
        )];
        let json = rules_to_json(&rules);
        assert_eq!(rules_from_json(&json), Ok(rules));
    }

    #[test]
    fn an_empty_or_bad_rule_list_is_handled() {
        assert_eq!(rules_from_json(""), Ok(Vec::new()));
        assert_eq!(rules_from_json("[]"), Ok(Vec::new()));
        assert!(rules_from_json("{").is_err());
        assert!(rules_from_json(r#"[{"group":"x"}]"#).is_err());
    }

    #[test]
    fn collections_default_to_none_in_json() {
        let space = SpaceId::random();
        let json = format!(r#"[{{"group":"g","space":"{space}","role":"member"}}]"#);
        let rules = rules_from_json(&json).expect("parses");
        assert_eq!(rules[0].collections, Vec::<Uuid>::new());
    }
}
