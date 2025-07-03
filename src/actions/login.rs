use crate::{UserRepository, AuthError};
pub struct LoginAction<R: UserRepository> {
    repository: R,
}
