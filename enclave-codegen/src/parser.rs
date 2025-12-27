//! Rust source file parser using `syn`.
//!
//! Extracts struct and enum definitions from Rust source files.

use std::fs;
use std::path::Path;

/// A parsed type definition.
#[derive(Debug, Clone)]
pub struct TypeDefinition {
    pub name: String,
    pub kind: TypeKind,
}

/// The kind of type (struct or enum).
#[derive(Debug, Clone)]
pub enum TypeKind {
    Struct { fields: Vec<Field> },
    Enum { variants: Vec<Variant> },
}

/// A struct field.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ty: RustType,
}

/// An enum variant.
#[derive(Debug, Clone)]
pub struct Variant {
    pub name: String,
    pub fields: VariantFields,
}

/// Fields within an enum variant.
#[derive(Debug, Clone)]
pub enum VariantFields {
    /// Unit variant: `Foo`
    Unit,
    /// Tuple variant: `Foo(String)`
    Tuple(Vec<RustType>),
    /// Struct variant: `Foo { bar: String }`
    Struct(Vec<Field>),
}

/// A Rust type representation.
#[derive(Debug, Clone)]
pub enum RustType {
    /// Simple type: `String`, `i32`, etc.
    Simple(String),
    /// Option type: `Option<T>`
    Option(Box<RustType>),
    /// Vec type: `Vec<T>`
    Vec(Box<RustType>),
    /// `HashMap` type: `HashMap<K, V>`
    HashMap(Box<RustType>, Box<RustType>),
    /// Generic type: `DateTime<Utc>`
    Generic(String, Vec<RustType>),
}

/// Error type for parsing operations.
#[derive(Debug)]
pub enum ParseError {
    FileNotFound(String),
    IoError(std::io::Error),
    SyntaxError(String),
    TypeNotFound(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::FileNotFound(path) => write!(f, "file not found: {path}"),
            ParseError::IoError(e) => write!(f, "IO error: {e}"),
            ParseError::SyntaxError(msg) => write!(f, "syntax error: {msg}"),
            ParseError::TypeNotFound(name) => write!(f, "type not found: {name}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::IoError(e)
    }
}

/// Parse a Rust source file and extract a specific type definition.
pub fn parse_type(source_dir: &Path, relative_path: &str, type_name: &str) -> Result<TypeDefinition, ParseError> {
    let file_path = source_dir.join(relative_path);

    if !file_path.exists() {
        return Err(ParseError::FileNotFound(file_path.display().to_string()));
    }

    let source = fs::read_to_string(&file_path)?;
    parse_type_from_source(&source, type_name)
}

/// Parse a type definition from source code string.
pub fn parse_type_from_source(source: &str, type_name: &str) -> Result<TypeDefinition, ParseError> {
    let syntax = syn::parse_file(source)
        .map_err(|e| ParseError::SyntaxError(e.to_string()))?;

    for item in syntax.items {
        if let Some(def) = extract_type_definition(&item, type_name) {
            return Ok(def);
        }
    }

    Err(ParseError::TypeNotFound(type_name.to_owned()))
}

/// Extract a type definition from a syn Item if it matches the target name.
fn extract_type_definition(item: &syn::Item, target_name: &str) -> Option<TypeDefinition> {
    match item {
        syn::Item::Struct(s) if s.ident == target_name => {
            Some(parse_struct(s))
        }
        syn::Item::Enum(e) if e.ident == target_name => {
            Some(parse_enum(e))
        }
        _ => None,
    }
}

/// Parse a struct definition.
fn parse_struct(s: &syn::ItemStruct) -> TypeDefinition {
    let fields = match &s.fields {
        syn::Fields::Named(named) => {
            named.named.iter()
                .filter_map(|f| {
                    let name = f.ident.as_ref()?.to_string();
                    let ty = parse_rust_type(&f.ty);
                    Some(Field { name, ty })
                })
                .collect()
        }
        syn::Fields::Unnamed(unnamed) => {
            unnamed.unnamed.iter()
                .enumerate()
                .map(|(i, f)| {
                    let ty = parse_rust_type(&f.ty);
                    Field { name: format!("field{i}"), ty }
                })
                .collect()
        }
        syn::Fields::Unit => Vec::new(),
    };

    TypeDefinition {
        name: s.ident.to_string(),
        kind: TypeKind::Struct { fields },
    }
}

/// Parse an enum definition.
fn parse_enum(e: &syn::ItemEnum) -> TypeDefinition {
    let variants = e.variants.iter()
        .map(|v| {
            let name = v.ident.to_string();
            let fields = match &v.fields {
                syn::Fields::Unit => VariantFields::Unit,
                syn::Fields::Unnamed(unnamed) => {
                    let types = unnamed.unnamed.iter()
                        .map(|f| parse_rust_type(&f.ty))
                        .collect();
                    VariantFields::Tuple(types)
                }
                syn::Fields::Named(named) => {
                    let fields = named.named.iter()
                        .filter_map(|f| {
                            let name = f.ident.as_ref()?.to_string();
                            let ty = parse_rust_type(&f.ty);
                            Some(Field { name, ty })
                        })
                        .collect();
                    VariantFields::Struct(fields)
                }
            };
            Variant { name, fields }
        })
        .collect();

    TypeDefinition {
        name: e.ident.to_string(),
        kind: TypeKind::Enum { variants },
    }
}

/// Parse a `syn::Type` into our `RustType` representation.
fn parse_rust_type(ty: &syn::Type) -> RustType {
    match ty {
        syn::Type::Path(type_path) => {
            parse_type_path(&type_path.path)
        }
        syn::Type::Reference(type_ref) => {
            // For references, we just care about the inner type
            parse_rust_type(&type_ref.elem)
        }
        _ => {
            // Fallback: convert to string representation
            RustType::Simple(quote::quote!(#ty).to_string())
        }
    }
}

/// Parse a `syn::Path` into a `RustType`.
fn parse_type_path(path: &syn::Path) -> RustType {
    // Get the last segment (e.g., `String` from `std::string::String`)
    let Some(segment) = path.segments.last() else {
        return RustType::Simple("()".to_owned());
    };

    let ident = segment.ident.to_string();

    // Check for generic arguments
    match &segment.arguments {
        syn::PathArguments::None => {
            RustType::Simple(ident)
        }
        syn::PathArguments::AngleBracketed(args) => {
            let type_args: Vec<RustType> = args.args.iter()
                .filter_map(|arg| {
                    if let syn::GenericArgument::Type(ty) = arg {
                        Some(parse_rust_type(ty))
                    } else {
                        None
                    }
                })
                .collect();

            match ident.as_str() {
                "Option" if type_args.len() == 1 => {
                    RustType::Option(Box::new(type_args.into_iter().next().unwrap_or(RustType::Simple("unknown".to_owned()))))
                }
                "Vec" if type_args.len() == 1 => {
                    RustType::Vec(Box::new(type_args.into_iter().next().unwrap_or(RustType::Simple("unknown".to_owned()))))
                }
                "HashMap" | "BTreeMap" if type_args.len() == 2 => {
                    let mut iter = type_args.into_iter();
                    let key = iter.next().unwrap_or(RustType::Simple("unknown".to_owned()));
                    let value = iter.next().unwrap_or(RustType::Simple("unknown".to_owned()));
                    RustType::HashMap(Box::new(key), Box::new(value))
                }
                _ => {
                    if type_args.is_empty() {
                        RustType::Simple(ident)
                    } else {
                        RustType::Generic(ident, type_args)
                    }
                }
            }
        }
        syn::PathArguments::Parenthesized(_) => {
            // Function types - just stringify
            RustType::Simple(quote::quote!(#path).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_struct() {
        let source = r#"
            pub struct User {
                pub id: i32,
                pub name: String,
            }
        "#;

        let def = parse_type_from_source(source, "User").unwrap();
        assert_eq!(def.name, "User");

        if let TypeKind::Struct { fields } = def.kind {
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].name, "id");
            assert_eq!(fields[1].name, "name");
        } else {
            panic!("Expected struct");
        }
    }

    #[test]
    fn test_parse_struct_with_option() {
        let source = r#"
            pub struct User {
                pub email: Option<String>,
            }
        "#;

        let def = parse_type_from_source(source, "User").unwrap();

        if let TypeKind::Struct { fields } = def.kind {
            assert_eq!(fields.len(), 1);
            assert!(matches!(fields[0].ty, RustType::Option(_)));
        } else {
            panic!("Expected struct");
        }
    }

    #[test]
    fn test_parse_simple_enum() {
        let source = r#"
            pub enum Status {
                Active,
                Inactive,
            }
        "#;

        let def = parse_type_from_source(source, "Status").unwrap();
        assert_eq!(def.name, "Status");

        if let TypeKind::Enum { variants } = def.kind {
            assert_eq!(variants.len(), 2);
            assert_eq!(variants[0].name, "Active");
            assert_eq!(variants[1].name, "Inactive");
            assert!(matches!(variants[0].fields, VariantFields::Unit));
        } else {
            panic!("Expected enum");
        }
    }

    #[test]
    fn test_parse_enum_with_data() {
        let source = r#"
            pub enum Error {
                NotFound,
                Database(String),
                Validation { field: String, message: String },
            }
        "#;

        let def = parse_type_from_source(source, "Error").unwrap();

        if let TypeKind::Enum { variants } = def.kind {
            assert_eq!(variants.len(), 3);
            assert!(matches!(variants[0].fields, VariantFields::Unit));
            assert!(matches!(variants[1].fields, VariantFields::Tuple(_)));
            assert!(matches!(variants[2].fields, VariantFields::Struct(_)));
        } else {
            panic!("Expected enum");
        }
    }

    #[test]
    fn test_type_not_found() {
        let source = "pub struct Foo {}";
        let result = parse_type_from_source(source, "Bar");
        assert!(matches!(result, Err(ParseError::TypeNotFound(_))));
    }
}
