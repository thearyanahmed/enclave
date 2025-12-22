use crate::{AuthError, UserRepository};

pub struct DeleteUserAction<U: UserRepository> {
    user_repository: U,
}

impl<U: UserRepository> DeleteUserAction<U> {
    pub fn new(user_repository: U) -> Self {
        DeleteUserAction { user_repository }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(name = "delete_user", skip_all, err))]
    pub async fn execute(&self, user_id: i32) -> Result<(), AuthError> {
        self.user_repository.delete_user(user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockUserRepository, User};

    #[tokio::test]
    async fn test_delete_user_success() {
        let user_repo = MockUserRepository::new();

        let user = User::mock_from_email("user@example.com");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = DeleteUserAction::new(user_repo);
        let result = action.execute(user_id).await;

        assert!(result.is_ok());

        // User should be deleted
        let found = action
            .user_repository
            .find_user_by_id(user_id)
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let user_repo = MockUserRepository::new();

        let action = DeleteUserAction::new(user_repo);
        let result = action.execute(999).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserNotFound);
    }
}
