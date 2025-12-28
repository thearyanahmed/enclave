//! # Enclave Codegen
//!
//! TypeScript and `JSDoc` code generator for Rust types.
//!
//! This crate provides tools to generate TypeScript type definitions and
//! JavaScript with `JSDoc` annotations from Rust source files without modifying
//! the original types.
//!
//! ## CLI Usage
//!
//! ```bash
//! # Generate TypeScript
//! enclave-codegen \
//!     --source ./src \
//!     --output ./types/typescript \
//!     --format typescript \
//!     --types "AuthUser:repository/user.rs"
//!
//! # Generate JavaScript with JSDoc
//! enclave-codegen \
//!     --source ./src \
//!     --output ./types/javascript \
//!     --format jsdoc \
//!     --types "AuthUser:repository/user.rs"
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

pub mod jsdoc;
pub mod parser;
pub mod typescript;

pub use jsdoc::generate_jsdoc;
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
#[allow(clippy::unwrap_used)]
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
        let source = r"
            use chrono::{DateTime, Utc};

            pub struct AuthUser {
                pub id: i32,
                pub email: String,
                pub name: String,
                pub email_verified_at: Option<DateTime<Utc>>,
                pub created_at: DateTime<Utc>,
            }
        ";

        let def = parse_type_from_source(source, "AuthUser").unwrap();
        let ts = generate_typescript(&def);

        assert!(ts.contains("export interface AuthUser"));
        assert!(ts.contains("id: number"));
        assert!(ts.contains("email: string"));
        assert!(ts.contains("name: string"));
        assert!(ts.contains("email_verified_at: string | null"));
        assert!(ts.contains("created_at: string"));
    }

    #[test]
    fn test_parse_auth_error_like_enum() {
        let source = r"
            pub enum AuthError {
                UserNotFound,
                UserAlreadyExists,
                InvalidCredentials,
                DatabaseError(String),
                Validation(ValidationError),
            }
        ";

        let def = parse_type_from_source(source, "AuthError").unwrap();
        let ts = generate_typescript(&def);

        assert!(ts.contains("export type AuthError ="));
        assert!(ts.contains("{ type: \"UserNotFound\" }"));
        assert!(ts.contains("{ type: \"UserAlreadyExists\" }"));
        assert!(ts.contains("{ type: \"InvalidCredentials\" }"));
        assert!(ts.contains("{ type: \"DatabaseError\"; value: string }"));
        assert!(ts.contains("{ type: \"Validation\"; value: ValidationError }"));
    }

    #[test]
    fn test_jsdoc_generation() {
        let source = r"
            /// A user in the system.
            pub struct AuthUser {
                /// The user's unique ID.
                pub id: i32,
                /// The user's email address.
                pub email: String,
            }
        ";

        let def = parse_type_from_source(source, "AuthUser").unwrap();
        let js = generate_jsdoc(&def);

        assert!(js.contains("@typedef {AuthUser} AuthUser"));
        assert!(js.contains("@property {number} id - The user's unique ID."));
        assert!(js.contains("@property {string} email - The user's email address."));
        assert!(js.contains("A user in the system."));
    }
}
