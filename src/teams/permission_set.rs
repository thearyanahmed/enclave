//! Compact permission storage for team members.
//!
//! `PermissionSet` provides a way to store and check multiple permissions
//! efficiently, with JSON serialization for database storage.

use std::collections::HashMap;

use super::traits::{Action, Permission, Resource};

/// A set of permissions for a team member.
///
/// Permissions are stored as a map of resources to their allowed actions.
/// This enables efficient lookup and compact JSON storage.
///
/// # Example
///
/// ```rust,ignore
/// use enclave::teams::PermissionSet;
///
/// let mut perms = PermissionSet::new();
/// perms.grant(AppResource::Project, AppAction::Create);
/// perms.grant(AppResource::Project, AppAction::Read);
/// perms.grant(AppResource::Member, AppAction::All);
///
/// assert!(perms.can(&AppResource::Project, &AppAction::Create));
/// assert!(perms.can(&AppResource::Member, &AppAction::Delete)); // All grants everything
/// ```
#[derive(Debug, Clone)]
pub struct PermissionSet<R, A>
where
    R: Resource,
    A: Action,
{
    /// Map of resource -> list of actions.
    permissions: HashMap<R, Vec<A>>,
}

impl<R, A> Default for PermissionSet<R, A>
where
    R: Resource,
    A: Action,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<R, A> PermissionSet<R, A>
where
    R: Resource,
    A: Action,
{
    /// Create an empty permission set.
    pub fn new() -> Self {
        Self {
            permissions: HashMap::new(),
        }
    }

    /// Grant a permission for a resource and action.
    pub fn grant(&mut self, resource: R, action: A) {
        self.permissions
            .entry(resource)
            .or_default()
            .push(action);
    }

    /// Check if the permission set allows an action on a resource.
    ///
    /// Returns true if:
    /// - The exact resource+action is granted, or
    /// - The resource has an "all" action granted
    pub fn can(&self, resource: &R, action: &A) -> bool {
        self.permissions
            .get(resource)
            .is_some_and(|actions| actions.iter().any(|a| a.is_all() || a == action))
    }

    /// Check if any permission in this set grants the requested access.
    pub fn has_permission<P>(&self, permission: &P) -> bool
    where
        P: Permission<Resource = R, Action = A>,
    {
        self.can(permission.resource(), permission.action())
    }

    /// Remove all permissions for a resource.
    pub fn revoke_resource(&mut self, resource: &R) {
        self.permissions.remove(resource);
    }

    /// Remove a specific action from a resource.
    pub fn revoke(&mut self, resource: &R, action: &A) {
        if let Some(actions) = self.permissions.get_mut(resource) {
            actions.retain(|a| a != action);
            if actions.is_empty() {
                self.permissions.remove(resource);
            }
        }
    }

    /// Get all resources that have permissions.
    pub fn resources(&self) -> impl Iterator<Item = &R> {
        self.permissions.keys()
    }

    /// Get all actions for a resource.
    pub fn actions_for(&self, resource: &R) -> Option<&[A]> {
        self.permissions.get(resource).map(Vec::as_slice)
    }

    /// Check if the permission set is empty.
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
    }

    /// Get the number of resources with permissions.
    pub fn len(&self) -> usize {
        self.permissions.len()
    }

    /// Serialize to JSON for database storage.
    ///
    /// Format: `{"resource1": ["action1", "action2"], "resource2": ["all"]}`
    pub fn to_json(&self) -> String {
        let map: HashMap<&str, Vec<&str>> = self
            .permissions
            .iter()
            .map(|(r, actions)| (r.as_str(), actions.iter().map(Action::as_str).collect()))
            .collect();

        serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_owned())
    }

    /// Deserialize from JSON.
    ///
    /// Returns None if parsing fails or if any resource/action is unrecognized.
    pub fn from_json(json: &str) -> Option<Self> {
        let map: HashMap<String, Vec<String>> = serde_json::from_str(json).ok()?;

        let mut permissions = HashMap::new();
        for (resource_str, action_strs) in map {
            let resource = R::from_str(&resource_str)?;
            let mut actions = Vec::new();
            for action_str in action_strs {
                actions.push(A::from_str(&action_str)?);
            }
            permissions.insert(resource, actions);
        }

        Some(Self { permissions })
    }
}

/// Builder for creating permission sets with a fluent API.
#[must_use]
pub struct PermissionSetBuilder<R, A>
where
    R: Resource,
    A: Action,
{
    set: PermissionSet<R, A>,
}

impl<R, A> PermissionSetBuilder<R, A>
where
    R: Resource,
    A: Action,
{
    /// Start building a new permission set.
    pub fn new() -> Self {
        Self {
            set: PermissionSet::new(),
        }
    }

    /// Grant a permission.
    pub fn grant(mut self, resource: R, action: A) -> Self {
        self.set.grant(resource, action);
        self
    }

    /// Build the permission set.
    pub fn build(self) -> PermissionSet<R, A> {
        self.set
    }
}

impl<R, A> Default for PermissionSetBuilder<R, A>
where
    R: Resource,
    A: Action,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    enum TestResource {
        Project,
        Member,
        Settings,
    }

    impl Resource for TestResource {
        fn as_str(&self) -> &'static str {
            match self {
                Self::Project => "project",
                Self::Member => "member",
                Self::Settings => "settings",
            }
        }

        fn from_str(s: &str) -> Option<Self> {
            match s {
                "project" => Some(Self::Project),
                "member" => Some(Self::Member),
                "settings" => Some(Self::Settings),
                _ => None,
            }
        }
    }

    #[derive(Clone, PartialEq, Debug)]
    enum TestAction {
        Create,
        Read,
        Update,
        Delete,
        All,
    }

    impl Action for TestAction {
        fn as_str(&self) -> &'static str {
            match self {
                Self::Create => "create",
                Self::Read => "read",
                Self::Update => "update",
                Self::Delete => "delete",
                Self::All => "all",
            }
        }

        fn from_str(s: &str) -> Option<Self> {
            match s {
                "create" => Some(Self::Create),
                "read" => Some(Self::Read),
                "update" => Some(Self::Update),
                "delete" => Some(Self::Delete),
                "all" => Some(Self::All),
                _ => None,
            }
        }

        fn is_all(&self) -> bool {
            matches!(self, Self::All)
        }
    }

    #[test]
    fn test_grant_and_check() {
        let mut perms = PermissionSet::new();
        perms.grant(TestResource::Project, TestAction::Create);
        perms.grant(TestResource::Project, TestAction::Read);

        assert!(perms.can(&TestResource::Project, &TestAction::Create));
        assert!(perms.can(&TestResource::Project, &TestAction::Read));
        assert!(!perms.can(&TestResource::Project, &TestAction::Delete));
        assert!(!perms.can(&TestResource::Member, &TestAction::Create));
    }

    #[test]
    fn test_all_action_grants_everything() {
        let mut perms = PermissionSet::new();
        perms.grant(TestResource::Project, TestAction::All);

        assert!(perms.can(&TestResource::Project, &TestAction::Create));
        assert!(perms.can(&TestResource::Project, &TestAction::Read));
        assert!(perms.can(&TestResource::Project, &TestAction::Update));
        assert!(perms.can(&TestResource::Project, &TestAction::Delete));
        // But not for other resources
        assert!(!perms.can(&TestResource::Member, &TestAction::Create));
    }

    #[test]
    fn test_revoke() {
        let mut perms = PermissionSet::new();
        perms.grant(TestResource::Project, TestAction::Create);
        perms.grant(TestResource::Project, TestAction::Read);

        perms.revoke(&TestResource::Project, &TestAction::Create);

        assert!(!perms.can(&TestResource::Project, &TestAction::Create));
        assert!(perms.can(&TestResource::Project, &TestAction::Read));
    }

    #[test]
    fn test_revoke_resource() {
        let mut perms = PermissionSet::new();
        perms.grant(TestResource::Project, TestAction::Create);
        perms.grant(TestResource::Project, TestAction::Read);

        perms.revoke_resource(&TestResource::Project);

        assert!(!perms.can(&TestResource::Project, &TestAction::Create));
        assert!(!perms.can(&TestResource::Project, &TestAction::Read));
    }

    #[test]
    fn test_json_roundtrip() {
        let mut perms = PermissionSet::new();
        perms.grant(TestResource::Project, TestAction::Create);
        perms.grant(TestResource::Project, TestAction::Read);
        perms.grant(TestResource::Member, TestAction::All);

        let json = perms.to_json();
        let parsed: PermissionSet<TestResource, TestAction> =
            PermissionSet::from_json(&json).expect("should parse");

        assert!(parsed.can(&TestResource::Project, &TestAction::Create));
        assert!(parsed.can(&TestResource::Project, &TestAction::Read));
        assert!(parsed.can(&TestResource::Member, &TestAction::Delete));
    }

    #[test]
    fn test_builder() {
        let perms = PermissionSetBuilder::new()
            .grant(TestResource::Project, TestAction::Create)
            .grant(TestResource::Project, TestAction::Read)
            .grant(TestResource::Settings, TestAction::All)
            .build();

        assert!(perms.can(&TestResource::Project, &TestAction::Create));
        assert!(perms.can(&TestResource::Settings, &TestAction::Update));
        assert!(!perms.can(&TestResource::Member, &TestAction::Create));
    }

    #[test]
    fn test_empty_set() {
        let perms: PermissionSet<TestResource, TestAction> = PermissionSet::new();

        assert!(perms.is_empty());
        assert_eq!(perms.len(), 0);
        assert!(!perms.can(&TestResource::Project, &TestAction::Create));
    }
}
