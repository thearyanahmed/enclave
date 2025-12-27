//! TypeScript code generator.
//!
//! Converts parsed Rust types to TypeScript interfaces and type aliases.

use crate::parser::{Field, RustType, TypeDefinition, TypeKind, Variant, VariantFields};
use std::collections::BTreeSet;
use std::fmt::Write;

/// Primitive types that don't need imports.
const PRIMITIVE_TYPES: &[&str] = &[
    "string",
    "number",
    "boolean",
    "void",
    "null",
    "undefined",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "f32",
    "f64",
    "String",
    "str",
    "&str",
    "bool",
    "()",
];

/// Generate TypeScript code for a type definition.
pub fn generate_typescript(def: &TypeDefinition) -> String {
    let mut imports = BTreeSet::new();
    let mut uses_secret_string = false;

    // Collect imports based on type kind
    match &def.kind {
        TypeKind::Struct { fields } => {
            for field in fields {
                collect_imports(&field.ty, &mut imports, &mut uses_secret_string);
            }
        }
        TypeKind::Enum { variants } => {
            for variant in variants {
                match &variant.fields {
                    VariantFields::Unit => {}
                    VariantFields::Tuple(types) => {
                        for ty in types {
                            collect_imports(ty, &mut imports, &mut uses_secret_string);
                        }
                    }
                    VariantFields::Struct(fields) => {
                        for field in fields {
                            collect_imports(&field.ty, &mut imports, &mut uses_secret_string);
                        }
                    }
                }
            }
        }
    }

    // Remove self-reference
    imports.remove(&def.name);

    let mut output = String::new();

    // Generate imports
    for import in &imports {
        let _ = writeln!(output, "import type {{ {import} }} from './{import}';");
    }

    // Add SecretString branded type if used
    if uses_secret_string {
        if !imports.is_empty() {
            output.push('\n');
        }
        output.push_str("/** Branded type for sensitive string data. Handle securely - do not log or expose. */\n");
        output.push_str(
            "export type SecretString = string & { readonly __brand: 'SecretString' };\n",
        );
    }

    if !imports.is_empty() || uses_secret_string {
        output.push('\n');
    }

    // Generate the type definition
    match &def.kind {
        TypeKind::Struct { fields } => {
            output.push_str(&generate_interface(&def.name, fields));
        }
        TypeKind::Enum { variants } => {
            output.push_str(&generate_union(&def.name, variants));
        }
    }

    output
}

/// Collect custom type imports from a Rust type.
fn collect_imports(ty: &RustType, imports: &mut BTreeSet<String>, uses_secret_string: &mut bool) {
    match ty {
        RustType::Simple(name) => {
            if name == "SecretString" {
                *uses_secret_string = true;
            } else if !PRIMITIVE_TYPES.contains(&name.as_str()) {
                imports.insert(name.clone());
            }
        }
        RustType::Option(inner) | RustType::Vec(inner) => {
            collect_imports(inner, imports, uses_secret_string);
        }
        RustType::HashMap(key, value) => {
            collect_imports(key, imports, uses_secret_string);
            collect_imports(value, imports, uses_secret_string);
        }
        RustType::Generic(name, args) => {
            if name == "SecretString" {
                *uses_secret_string = true;
                // Don't recurse into SecretString args
            } else if name == "DateTime" {
                // DateTime<Utc> maps to string, don't import type args
            } else {
                if !PRIMITIVE_TYPES.contains(&name.as_str()) {
                    imports.insert(name.clone());
                }
                for arg in args {
                    collect_imports(arg, imports, uses_secret_string);
                }
            }
        }
    }
}

/// Generate a TypeScript interface from struct fields.
fn generate_interface(name: &str, fields: &[Field]) -> String {
    let mut output = format!("export interface {name} {{\n");

    for field in fields {
        let (ts_type, optional) = rust_type_to_typescript(&field.ty);
        let opt_marker = if optional { "?" } else { "" };
        let _ = writeln!(output, "  {}{}: {};", field.name, opt_marker, ts_type);
    }

    output.push_str("}\n");
    output
}

/// Generate a TypeScript discriminated union from enum variants.
fn generate_union(name: &str, variants: &[Variant]) -> String {
    let mut output = format!("export type {name} =\n");

    for (i, variant) in variants.iter().enumerate() {
        let variant_type = match &variant.fields {
            VariantFields::Unit => {
                format!("  | {{ type: \"{}\" }}", variant.name)
            }
            VariantFields::Tuple(types) => {
                if types.len() == 1 {
                    let (ts_type, _) = rust_type_to_typescript(&types[0]);
                    format!("  | {{ type: \"{}\"; value: {} }}", variant.name, ts_type)
                } else {
                    let ts_types: Vec<String> =
                        types.iter().map(|t| rust_type_to_typescript(t).0).collect();
                    format!(
                        "  | {{ type: \"{}\"; value: [{}] }}",
                        variant.name,
                        ts_types.join(", ")
                    )
                }
            }
            VariantFields::Struct(fields) => {
                let mut field_strs = Vec::new();
                for field in fields {
                    let (ts_type, optional) = rust_type_to_typescript(&field.ty);
                    let opt_marker = if optional { "?" } else { "" };
                    field_strs.push(format!("{}{}: {}", field.name, opt_marker, ts_type));
                }
                format!(
                    "  | {{ type: \"{}\"; {} }}",
                    variant.name,
                    field_strs.join("; ")
                )
            }
        };

        output.push_str(&variant_type);

        if i < variants.len() - 1 {
            output.push('\n');
        }
    }

    output.push_str(";\n");
    output
}

/// Convert a Rust type to TypeScript type.
/// Returns `(type_string, is_optional)`.
fn rust_type_to_typescript(ty: &RustType) -> (String, bool) {
    match ty {
        RustType::Simple(name) => {
            let ts_type = match name.as_str() {
                // Numeric types (all map to number)
                "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64"
                | "u128" | "usize" | "f32" | "f64" => "number",

                // String types
                "String" | "str" | "&str" => "string",

                // Boolean
                "bool" => "boolean",

                // Unit type
                "()" => "void",

                // Keep other types as-is (custom types)
                other => other,
            };
            (ts_type.to_owned(), false)
        }
        RustType::Option(inner) => {
            let (inner_type, _) = rust_type_to_typescript(inner);
            (format!("{inner_type} | null"), true)
        }
        RustType::Vec(inner) => {
            let (inner_type, _) = rust_type_to_typescript(inner);
            (format!("{inner_type}[]"), false)
        }
        RustType::HashMap(key, value) => {
            let (key_type, _) = rust_type_to_typescript(key);
            let (value_type, _) = rust_type_to_typescript(value);
            (format!("Record<{key_type}, {value_type}>"), false)
        }
        RustType::Generic(name, args) => {
            // Handle well-known generic types
            match name.as_str() {
                // `DateTime<Utc>` -> string (ISO 8601)
                "DateTime" => ("string".to_owned(), false),

                // `SecretString` -> branded type for security awareness
                "SecretString" => ("SecretString".to_owned(), false),

                // For other generics, include type parameters
                _ => {
                    let ts_args: Vec<String> =
                        args.iter().map(|a| rust_type_to_typescript(a).0).collect();
                    if ts_args.is_empty() {
                        (name.clone(), false)
                    } else {
                        (format!("{}<{}>", name, ts_args.join(", ")), false)
                    }
                }
            }
        }
    }
}

/// Generate an index.ts file that re-exports all types.
pub fn generate_index(type_names: &[String]) -> String {
    let mut output = String::new();

    for name in type_names {
        let _ = writeln!(output, "export {{ {name} }} from './{name}';");
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_struct() {
        let def = TypeDefinition {
            name: "User".to_owned(),
            doc: None,
            kind: TypeKind::Struct {
                fields: vec![
                    Field {
                        name: "id".to_owned(),
                        doc: None,
                        ty: RustType::Simple("i32".to_owned()),
                    },
                    Field {
                        name: "name".to_owned(),
                        doc: None,
                        ty: RustType::Simple("String".to_owned()),
                    },
                ],
            },
        };

        let ts = generate_typescript(&def);
        assert!(ts.contains("export interface User"));
        assert!(ts.contains("id: number"));
        assert!(ts.contains("name: string"));
    }

    #[test]
    fn test_optional_field() {
        let def = TypeDefinition {
            name: "User".to_owned(),
            doc: None,
            kind: TypeKind::Struct {
                fields: vec![Field {
                    name: "email".to_owned(),
                    doc: None,
                    ty: RustType::Option(Box::new(RustType::Simple("String".to_owned()))),
                }],
            },
        };

        let ts = generate_typescript(&def);
        assert!(ts.contains("email?: string | null"));
    }

    #[test]
    fn test_vec_field() {
        let def = TypeDefinition {
            name: "Team".to_owned(),
            doc: None,
            kind: TypeKind::Struct {
                fields: vec![Field {
                    name: "members".to_owned(),
                    doc: None,
                    ty: RustType::Vec(Box::new(RustType::Simple("i32".to_owned()))),
                }],
            },
        };

        let ts = generate_typescript(&def);
        assert!(ts.contains("members: number[]"));
    }

    #[test]
    fn test_datetime_field() {
        let def = TypeDefinition {
            name: "Event".to_owned(),
            doc: None,
            kind: TypeKind::Struct {
                fields: vec![Field {
                    name: "created_at".to_owned(),
                    doc: None,
                    ty: RustType::Generic(
                        "DateTime".to_owned(),
                        vec![RustType::Simple("Utc".to_owned())],
                    ),
                }],
            },
        };

        let ts = generate_typescript(&def);
        assert!(ts.contains("created_at: string"));
    }

    #[test]
    fn test_simple_enum() {
        let def = TypeDefinition {
            name: "Status".to_owned(),
            doc: None,
            kind: TypeKind::Enum {
                variants: vec![
                    Variant {
                        name: "Active".to_owned(),
                        doc: None,
                        fields: VariantFields::Unit,
                    },
                    Variant {
                        name: "Inactive".to_owned(),
                        doc: None,
                        fields: VariantFields::Unit,
                    },
                ],
            },
        };

        let ts = generate_typescript(&def);
        assert!(ts.contains("export type Status ="));
        assert!(ts.contains("{ type: \"Active\" }"));
        assert!(ts.contains("{ type: \"Inactive\" }"));
    }

    #[test]
    fn test_enum_with_data() {
        let def = TypeDefinition {
            name: "Error".to_owned(),
            doc: None,
            kind: TypeKind::Enum {
                variants: vec![
                    Variant {
                        name: "NotFound".to_owned(),
                        doc: None,
                        fields: VariantFields::Unit,
                    },
                    Variant {
                        name: "Message".to_owned(),
                        doc: None,
                        fields: VariantFields::Tuple(vec![RustType::Simple("String".to_owned())]),
                    },
                ],
            },
        };

        let ts = generate_typescript(&def);
        assert!(ts.contains("{ type: \"NotFound\" }"));
        assert!(ts.contains("{ type: \"Message\"; value: string }"));
    }

    #[test]
    fn test_generate_index() {
        let names = vec!["User".to_owned(), "Team".to_owned(), "Error".to_owned()];
        let index = generate_index(&names);

        assert!(index.contains("export { User } from './User'"));
        assert!(index.contains("export { Team } from './Team'"));
        assert!(index.contains("export { Error } from './Error'"));
    }
}
