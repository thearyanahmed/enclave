use crate::UserRepository;

pub struct SignupAction<R> {
    repository: R,
}

impl <R: UserRepository> SignupAction<R> {
    pub fn new(repository: R) -> Self {
        SignupAction { repository }
    }

    pub async fn execute(&self, email: &str, password: &str) -> Result<R::User, String> {
        // Check if the user already exists
        if let Ok(Some(_)) = self.repository.find_user_by_email(email).await {
            return Err("User already exists".to_string());
        }

        // Hash the password (this is a placeholder, use a proper hashing function)
        let hashed = hash_password(password)?;

        self.repository.create_user(email, &hashed).await
    }
}

fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = b"fixedsalt"; // replace with real salt/random 
    argon2::hash_encoded(password.as_bytes(), salt, &Config::default())
        .map_err(|e| AuthError::Other(e.to_string()))
}
