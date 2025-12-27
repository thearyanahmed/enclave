//! Traits for user-defined roles and permissions.
//!
//! Users define their own Role, Resource, and Action enums for type safety.
//! These traits provide the interface for serialization and permission checking.

/// A role that can be assigned to team members.
///
/// Implement this for your application's role enum.
///
/// # Example
///
/// ```rust
/// use enclave::teams::Role;
///
/// #[derive(Clone, PartialEq)]
/// enum AppRole {
///     Owner,
///     Admin,
///     Member,
/// }
///
/// impl Role for AppRole {
///     fn as_str(&self) -> &'static str {
///         match self {
///             Self::Owner => "owner",
///             Self::Admin => "admin",
///             Self::Member => "member",
///         }
///     }
///
///     fn from_str(s: &str) -> Option<Self> {
///         match s {
///             "owner" => Some(Self::Owner),
///             "admin" => Some(Self::Admin),
///             "member" => Some(Self::Member),
///             _ => None,
///         }
///     }
/// }
/// ```
pub trait Role: Clone + Send + Sync + 'static {
    /// Convert to string for database storage.
    fn as_str(&self) -> &'static str;

    /// Parse from database string.
    fn from_str(s: &str) -> Option<Self>;
}

/// A resource that can have permissions.
///
/// Resources represent things in your application that can be protected
/// (e.g., "project", "member", "settings", "billing").
///
/// # Example
///
/// ```rust
/// use enclave::teams::Resource;
///
/// #[derive(Clone, PartialEq, Eq, Hash)]
/// enum AppResource {
///     Project,
///     Member,
///     Settings,
/// }
///
/// impl Resource for AppResource {
///     fn as_str(&self) -> &'static str {
///         match self {
///             Self::Project => "project",
///             Self::Member => "member",
///             Self::Settings => "settings",
///         }
///     }
///
///     fn from_str(s: &str) -> Option<Self> {
///         match s {
///             "project" => Some(Self::Project),
///             "member" => Some(Self::Member),
///             "settings" => Some(Self::Settings),
///             _ => None,
///         }
///     }
/// }
/// ```
pub trait Resource: Clone + PartialEq + Eq + std::hash::Hash + Send + Sync + 'static {
    /// Convert to string for database storage.
    fn as_str(&self) -> &'static str;

    /// Parse from database string.
    fn from_str(s: &str) -> Option<Self>;
}

/// An action that can be performed on a resource.
///
/// Actions represent operations like "create", "read", "update", "delete".
/// Include an "all" variant for granting full access to a resource.
///
/// # Example
///
/// ```rust
/// use enclave::teams::Action;
///
/// #[derive(Clone, PartialEq)]
/// enum AppAction {
///     Create,
///     Read,
///     Update,
///     Delete,
///     All,
/// }
///
/// impl Action for AppAction {
///     fn as_str(&self) -> &'static str {
///         match self {
///             Self::Create => "create",
///             Self::Read => "read",
///             Self::Update => "update",
///             Self::Delete => "delete",
///             Self::All => "all",
///         }
///     }
///
///     fn from_str(s: &str) -> Option<Self> {
///         match s {
///             "create" => Some(Self::Create),
///             "read" => Some(Self::Read),
///             "update" => Some(Self::Update),
///             "delete" => Some(Self::Delete),
///             "all" => Some(Self::All),
///             _ => None,
///         }
///     }
///
///     fn is_all(&self) -> bool {
///         matches!(self, Self::All)
///     }
/// }
/// ```
pub trait Action: Clone + PartialEq + Send + Sync + 'static {
    /// Convert to string for database storage.
    fn as_str(&self) -> &'static str;

    /// Parse from database string.
    fn from_str(s: &str) -> Option<Self>;

    /// Returns true if this action grants all actions on the resource.
    ///
    /// Override this to return `true` for your "all" variant.
    fn is_all(&self) -> bool {
        false
    }
}

/// A permission combining a resource and action.
///
/// This trait allows for custom permission types that can check
/// if one permission grants another (e.g., "all" grants any action).
pub trait Permission: Clone + PartialEq + Send + Sync + 'static {
    /// The resource type.
    type Resource: Resource;
    /// The action type.
    type Action: Action;

    /// Get the resource this permission applies to.
    fn resource(&self) -> &Self::Resource;

    /// Get the action this permission grants.
    fn action(&self) -> &Self::Action;

    /// Check if this permission grants access for a specific action.
    ///
    /// Returns true if the resource matches and either:
    /// - The action matches exactly, or
    /// - This permission's action is "all"
    fn grants(&self, resource: &Self::Resource, action: &Self::Action) -> bool {
        self.resource() == resource && (self.action().is_all() || self.action() == action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    enum TestResource {
        Project,
        Member,
    }

    impl Resource for TestResource {
        fn as_str(&self) -> &'static str {
            match self {
                Self::Project => "project",
                Self::Member => "member",
            }
        }

        fn from_str(s: &str) -> Option<Self> {
            match s {
                "project" => Some(Self::Project),
                "member" => Some(Self::Member),
                _ => None,
            }
        }
    }

    #[derive(Clone, PartialEq, Debug)]
    enum TestAction {
        Create,
        Read,
        All,
    }

    impl Action for TestAction {
        fn as_str(&self) -> &'static str {
            match self {
                Self::Create => "create",
                Self::Read => "read",
                Self::All => "all",
            }
        }

        fn from_str(s: &str) -> Option<Self> {
            match s {
                "create" => Some(Self::Create),
                "read" => Some(Self::Read),
                "all" => Some(Self::All),
                _ => None,
            }
        }

        fn is_all(&self) -> bool {
            matches!(self, Self::All)
        }
    }

    #[derive(Clone, PartialEq, Debug)]
    struct TestPermission {
        resource: TestResource,
        action: TestAction,
    }

    impl Permission for TestPermission {
        type Resource = TestResource;
        type Action = TestAction;

        fn resource(&self) -> &Self::Resource {
            &self.resource
        }

        fn action(&self) -> &Self::Action {
            &self.action
        }
    }

    #[test]
    fn test_permission_grants_exact() {
        let perm = TestPermission {
            resource: TestResource::Project,
            action: TestAction::Create,
        };

        assert!(perm.grants(&TestResource::Project, &TestAction::Create));
        assert!(!perm.grants(&TestResource::Project, &TestAction::Read));
        assert!(!perm.grants(&TestResource::Member, &TestAction::Create));
    }

    #[test]
    fn test_permission_grants_all() {
        let perm = TestPermission {
            resource: TestResource::Project,
            action: TestAction::All,
        };

        assert!(perm.grants(&TestResource::Project, &TestAction::Create));
        assert!(perm.grants(&TestResource::Project, &TestAction::Read));
        assert!(!perm.grants(&TestResource::Member, &TestAction::Create));
    }

    #[test]
    fn test_role_roundtrip() {
        #[derive(Clone, PartialEq, Debug)]
        enum TestRole {
            Admin,
        }

        impl Role for TestRole {
            fn as_str(&self) -> &'static str {
                "admin"
            }

            fn from_str(s: &str) -> Option<Self> {
                (s == "admin").then_some(Self::Admin)
            }
        }

        let role = TestRole::Admin;
        let s = role.as_str();
        let parsed = TestRole::from_str(s);
        assert_eq!(parsed, Some(TestRole::Admin));
    }
}
