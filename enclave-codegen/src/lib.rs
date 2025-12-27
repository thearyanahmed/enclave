//! # Enclave Codegen
//!
//! TypeScript code generator for Rust types.
//!
//! This crate provides tools to generate TypeScript type definitions from Rust
//! source files without modifying the original types.
//!
//! ## CLI Usage
//!
//! ```bash
//! enclave-codegen \
//!     --source ./src \
//!     --output ./types \
//!     --types "AuthUser:repository/user.rs" \
//!     --types "AuthError:lib.rs"
//! ```
//!
//! ## Macro Usage
//!
//! Define which types to export in an `autogen.rs` file:
//!
//! ```rust,ignore
//! enclave_codegen::export_types! {
//!     AuthUser => "repository/user.rs",
//!     AuthError => "lib.rs",
//!     Team => "teams/types.rs",
//! }
//! ```
//!
//! Then use the generated `TYPES` constant with a build script or the CLI.

pub mod parser;
pub mod typescript;

pub use parser::{ParseError, TypeDefinition, parse_type, parse_type_from_source};
pub use typescript::{generate_index, generate_typescript};

/// Define types to export to TypeScript.
///
/// Creates a constant `TYPES: &[(&str, &str)]` containing pairs of
/// `(type_name, source_path)`.
///
/// # Example
///
/// ```rust
/// enclave_codegen::export_types! {
///     AuthUser => "repository/user.rs",
///     AuthError => "lib.rs",
/// }
///
/// // Creates:
/// // pub const TYPES: &[(&str, &str)] = &[
/// //     ("AuthUser", "repository/user.rs"),
/// //     ("AuthError", "lib.rs"),
/// // ];
/// ```
#[macro_export]
macro_rules! export_types {
    ($($name:ident => $path:literal),* $(,)?) => {
        /// Types to export to TypeScript.
        pub const TYPES: &[(&str, &str)] = &[
            $((stringify!($name), $path)),*
        ];
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    export_types! {
        TestType => "test.rs",
        AnotherType => "another/file.rs",
    }

    #[test]
    fn test_export_types_macro() {
        assert_eq!(TYPES.len(), 2);
        assert_eq!(TYPES[0], ("TestType", "test.rs"));
        assert_eq!(TYPES[1], ("AnotherType", "another/file.rs"));
    }

    #[test]
    fn test_parse_auth_user_like_struct() {
        let source = r#"
            use chrono::{DateTime, Utc};

            pub struct AuthUser {
                pub id: i32,
                pub email: String,
                pub name: String,
                pub email_verified_at: Option<DateTime<Utc>>,
                pub created_at: DateTime<Utc>,
            }
        "#;

        let def = parse_type_from_source(source, "AuthUser").unwrap();
        let ts = generate_typescript(&def);

        assert!(ts.contains("export interface AuthUser"));
        assert!(ts.contains("id: number"));
        assert!(ts.contains("email: string"));
        assert!(ts.contains("name: string"));
        assert!(ts.contains("email_verified_at?: string | null"));
        assert!(ts.contains("created_at: string"));
    }

    #[test]
    fn test_parse_auth_error_like_enum() {
        let source = r#"
            pub enum AuthError {
                UserNotFound,
                UserAlreadyExists,
                InvalidCredentials,
                DatabaseError(String),
                Validation(ValidationError),
            }
        "#;

        let def = parse_type_from_source(source, "AuthError").unwrap();
        let ts = generate_typescript(&def);

        assert!(ts.contains("export type AuthError ="));
        assert!(ts.contains("{ type: \"UserNotFound\" }"));
        assert!(ts.contains("{ type: \"UserAlreadyExists\" }"));
        assert!(ts.contains("{ type: \"InvalidCredentials\" }"));
        assert!(ts.contains("{ type: \"DatabaseError\"; value: string }"));
        assert!(ts.contains("{ type: \"Validation\"; value: ValidationError }"));
    }
}
