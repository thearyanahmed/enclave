pub mod change_password;
pub mod delete_user;
pub mod forgot_password;
pub mod get_user;
pub mod login;
pub mod logout;
pub mod prune_expired;
pub mod refresh_token;
#[cfg(feature = "magic_link")]
pub mod request_magic_link;
pub mod reset_password;
pub mod send_verification;
pub mod signup;
pub mod update_user;
pub mod verify_email;
#[cfg(feature = "magic_link")]
pub mod verify_magic_link;

pub use change_password::{ChangePasswordAction, ChangePasswordConfig, NoTokenRevocation};
pub use delete_user::DeleteUserAction;
#[cfg(feature = "rate_limit")]
pub use forgot_password::RateLimitConfig;
pub use forgot_password::{ForgotPasswordAction, ForgotPasswordConfig};
pub use get_user::GetUserAction;
pub use login::{LoginAction, LoginConfig};
pub use logout::LogoutAction;
pub use prune_expired::{PruneExpiredTokensAction, PruneResult};
pub use refresh_token::{RefreshTokenAction, RefreshTokenConfig};
#[cfg(all(feature = "magic_link", feature = "rate_limit"))]
pub use request_magic_link::MagicLinkRateLimitConfig;
#[cfg(feature = "magic_link")]
pub use request_magic_link::{MagicLinkConfig, RequestMagicLinkAction};
pub use reset_password::ResetPasswordAction;
pub use send_verification::{SendVerificationAction, SendVerificationConfig};
pub use signup::SignupAction;
pub use update_user::UpdateUserAction;
pub use verify_email::VerifyEmailAction;
#[cfg(feature = "magic_link")]
pub use verify_magic_link::{VerifyMagicLinkAction, VerifyMagicLinkConfig};
