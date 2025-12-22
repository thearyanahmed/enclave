use crate::{AuthError, User, UserRepository};

pub struct GetUserAction<U: UserRepository> {
    user_repository: U,
}

impl<U: UserRepository> GetUserAction<U> {
    pub fn new(user_repository: U) -> Self {
        Self { user_repository }
    }

    pub async fn execute(&self, user_id: i32) -> Result<User, AuthError> {
        let user = self.user_repository.find_user_by_id(user_id).await?;

        match user {
            Some(user) => Ok(user),
            None => Err(AuthError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockUserRepository, User};

    #[tokio::test]
    async fn test_get_user_success() {
        let user_repo = MockUserRepository::new();

        let user = User::mock_from_email("user@example.com");
        let user_id = user.id;
        user_repo.users.lock().unwrap().push(user);

        let action = GetUserAction::new(user_repo);
        let result = action.execute(user_id).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.email, "user@example.com");
    }

    #[tokio::test]
    async fn test_get_user_not_found() {
        let user_repo = MockUserRepository::new();

        let action = GetUserAction::new(user_repo);
        let result = action.execute(999).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::UserNotFound);
    }
}
