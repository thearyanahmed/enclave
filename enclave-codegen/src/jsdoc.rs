//! `JSDoc` code generator.
//!
//! Converts parsed Rust types to JavaScript with `JSDoc` type annotations.

use crate::parser::{Field, RustType, TypeDefinition, TypeKind, Variant, VariantFields};
use std::fmt::Write;

/// Generate `JSDoc` code for a type definition.
pub fn generate_jsdoc(def: &TypeDefinition) -> String {
    match &def.kind {
        TypeKind::Struct { fields } => generate_typedef(&def.name, def.doc.as_ref(), fields),
        TypeKind::Enum { variants } => {
            generate_union_typedef(&def.name, def.doc.as_ref(), variants)
        }
    }
}

/// Generate a `JSDoc` `@typedef` from struct fields.
fn generate_typedef(name: &str, doc: Option<&String>, fields: &[Field]) -> String {
    let mut output = String::new();

    output.push_str("/**\n");

    // Add type description if available
    if let Some(d) = doc {
        for line in d.lines() {
            let _ = writeln!(output, " * {line}");
        }
        output.push_str(" *\n");
    }

    // Add @typedef
    let _ = writeln!(output, " * @typedef {{{name}}} {name}");

    // Add @property for each field
    for field in fields {
        let (js_type, optional) = rust_type_to_jsdoc(&field.ty);
        let opt_marker = if optional { "[" } else { "" };
        let opt_end = if optional { "]" } else { "" };

        if let Some(field_doc) = &field.doc {
            let _ = writeln!(
                output,
                " * @property {{{js_type}}} {opt_marker}{}{opt_end} - {field_doc}",
                field.name
            );
        } else {
            let _ = writeln!(
                output,
                " * @property {{{js_type}}} {opt_marker}{}{opt_end}",
                field.name
            );
        }
    }

    output.push_str(" */\n");
    output
}

/// Generate a `JSDoc` `@typedef` union from enum variants.
fn generate_union_typedef(name: &str, doc: Option<&String>, variants: &[Variant]) -> String {
    let mut output = String::new();

    // Generate individual variant types
    for variant in variants {
        let variant_name = format!("{name}_{}", variant.name);
        let variant_type = match &variant.fields {
            VariantFields::Unit => {
                format!("{{ type: '{}' }}", variant.name)
            }
            VariantFields::Tuple(types) => {
                if types.len() == 1 {
                    let (js_type, _) = rust_type_to_jsdoc(&types[0]);
                    format!("{{ type: '{}', value: {} }}", variant.name, js_type)
                } else {
                    let js_types: Vec<String> =
                        types.iter().map(|t| rust_type_to_jsdoc(t).0).collect();
                    format!(
                        "{{ type: '{}', value: [{}] }}",
                        variant.name,
                        js_types.join(", ")
                    )
                }
            }
            VariantFields::Struct(fields) => {
                let mut field_strs = vec![format!("type: '{}'", variant.name)];
                for field in fields {
                    let (js_type, _) = rust_type_to_jsdoc(&field.ty);
                    field_strs.push(format!("{}: {}", field.name, js_type));
                }
                format!("{{ {} }}", field_strs.join(", "))
            }
        };

        output.push_str("/**\n");
        if let Some(variant_doc) = &variant.doc {
            let _ = writeln!(output, " * {variant_doc}");
            output.push_str(" *\n");
        }
        let _ = writeln!(output, " * @typedef {{{variant_type}}} {variant_name}");
        output.push_str(" */\n\n");
    }

    // Generate union type
    output.push_str("/**\n");
    if let Some(d) = doc {
        for line in d.lines() {
            let _ = writeln!(output, " * {line}");
        }
        output.push_str(" *\n");
    }

    let variant_names: Vec<String> = variants
        .iter()
        .map(|v| format!("{name}_{}", v.name))
        .collect();
    let _ = writeln!(
        output,
        " * @typedef {{({})}} {name}",
        variant_names.join(" | ")
    );
    output.push_str(" */\n");

    output
}

/// Convert a Rust type to `JSDoc` type.
/// Returns `(type_string, is_optional)`.
fn rust_type_to_jsdoc(ty: &RustType) -> (String, bool) {
    match ty {
        RustType::Simple(name) => {
            let js_type = match name.as_str() {
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
            (js_type.to_owned(), false)
        }
        RustType::Option(inner) => {
            let (inner_type, _) = rust_type_to_jsdoc(inner);
            (format!("({inner_type} | null)"), true)
        }
        RustType::Vec(inner) => {
            let (inner_type, _) = rust_type_to_jsdoc(inner);
            (format!("{inner_type}[]"), false)
        }
        RustType::HashMap(key, value) => {
            let (key_type, _) = rust_type_to_jsdoc(key);
            let (value_type, _) = rust_type_to_jsdoc(value);
            (format!("Object.<{key_type}, {value_type}>"), false)
        }
        RustType::Generic(name, args) => {
            // Handle well-known generic types
            match name.as_str() {
                // `DateTime<Utc>` -> string (ISO 8601), `SecretString` -> string
                "DateTime" | "SecretString" => ("string".to_owned(), false),

                // For other generics, include type parameters
                _ => {
                    let js_args: Vec<String> =
                        args.iter().map(|a| rust_type_to_jsdoc(a).0).collect();
                    if js_args.is_empty() {
                        (name.clone(), false)
                    } else {
                        (format!("{}<{}>", name, js_args.join(", ")), false)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_struct() {
        let def = TypeDefinition {
            name: "User".to_owned(),
            doc: Some("A user in the system.".to_owned()),
            kind: TypeKind::Struct {
                fields: vec![
                    Field {
                        name: "id".to_owned(),
                        doc: Some("The user ID.".to_owned()),
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

        let js = generate_jsdoc(&def);
        assert!(js.contains("@typedef {User} User"));
        assert!(js.contains("@property {number} id - The user ID."));
        assert!(js.contains("@property {string} name"));
        assert!(js.contains("A user in the system."));
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

        let js = generate_jsdoc(&def);
        assert!(js.contains("@property {(string | null)} [email]"));
    }

    #[test]
    fn test_simple_enum() {
        let def = TypeDefinition {
            name: "Status".to_owned(),
            doc: Some("Status enumeration.".to_owned()),
            kind: TypeKind::Enum {
                variants: vec![
                    Variant {
                        name: "Active".to_owned(),
                        doc: Some("The item is active.".to_owned()),
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

        let js = generate_jsdoc(&def);
        assert!(js.contains("@typedef {{ type: 'Active' }} Status_Active"));
        assert!(js.contains("@typedef {{ type: 'Inactive' }} Status_Inactive"));
        assert!(js.contains("@typedef {(Status_Active | Status_Inactive)} Status"));
        assert!(js.contains("The item is active."));
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

        let js = generate_jsdoc(&def);
        assert!(js.contains("@typedef {{ type: 'NotFound' }} Error_NotFound"));
        assert!(js.contains("@typedef {{ type: 'Message', value: string }} Error_Message"));
    }
}
