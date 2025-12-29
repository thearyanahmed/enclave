//! define your own Role, Resource, and Action enums and implement these traits.

/// implement for your role enum (Owner, Admin, Member, etc.)
pub trait Role: Clone + Send + Sync + 'static {
    fn as_str(&self) -> &'static str;
    fn from_str(s: &str) -> Option<Self>;
}

/// implement for things that can be protected (Project, Settings, etc.)
pub trait Resource: Clone + PartialEq + Eq + std::hash::Hash + Send + Sync + 'static {
    fn as_str(&self) -> &'static str;
    fn from_str(s: &str) -> Option<Self>;
}

/// implement for your action enum (Create, Read, Update, Delete, All, etc.)
pub trait Action: Clone + PartialEq + Send + Sync + 'static {
    fn as_str(&self) -> &'static str;
    fn from_str(s: &str) -> Option<Self>;

    /// override to return true for your "all" variant that grants full access
    fn is_all(&self) -> bool {
        false
    }
}

/// combines resource + action, with support for "all" granting any action
pub trait Permission: Clone + PartialEq + Send + Sync + 'static {
    type Resource: Resource;
    type Action: Action;

    fn resource(&self) -> &Self::Resource;
    fn action(&self) -> &Self::Action;

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
