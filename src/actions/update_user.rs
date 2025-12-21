use crate::{AuthError, User, UserRepository};

pub struct UpdateUserAction<U: UserRepository> {
    user_repository: U,
}

impl<U: UserRepository> UpdateUserAction<U> {
    pub fn new(user_repository: U) -> Self {
        UpdateUserAction { user_repository }
    }

    pub async fn execute(&self, user_id: i32, name: &str, email: &str) -> Result<User, AuthError> {
        self.user_repository.update_user(user_id, name, email).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockUserRepository, User};

    #[tokio::test]
    async fn test_update_user_success() {
        let user_repo = MockUserRepository::new();

        let user = User::mock_from_email("user@example.com");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = UpdateUserAction::new(user_repo);
        let result = action.execute(user_id, "New Name", "new@example.com").await;

        assert!(result.is_ok());
        let updated_user = result.unwrap();
        assert_eq!(updated_user.name, "New Name");
        assert_eq!(updated_user.email, "new@example.com");
    }

    #[tokio::test]
    async fn test_update_user_not_found() {
        let user_repo = MockUserRepository::new();

        let action = UpdateUserAction::new(user_repo);
        let result = action.execute(999, "Name", "email@example.com").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserNotFound);
    }
}
