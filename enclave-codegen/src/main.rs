//! Enclave TypeScript/`JSDoc` code generator CLI.
//!
//! Generates TypeScript type definitions or JavaScript with `JSDoc` annotations
//! from Rust source files.
//!
//! # Usage
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

use clap::{Parser, ValueEnum};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

mod jsdoc;
mod parser;
mod typescript;

/// Output format for generated code.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum OutputFormat {
    /// Generate TypeScript interfaces and type aliases.
    #[default]
    Typescript,
    /// Generate JavaScript with `JSDoc` type annotations.
    Jsdoc,
}

/// TypeScript/`JSDoc` code generator for Rust types.
#[derive(Parser, Debug)]
#[command(name = "enclave-codegen")]
#[command(
    version,
    about = "Generate TypeScript/JSDoc types from Rust source files"
)]
struct Cli {
    /// Working directory (changes to this directory before running).
    #[arg(short = 'C', long = "dir")]
    dir: Option<PathBuf>,

    /// Path to the Rust source directory (relative to working directory).
    #[arg(short, long)]
    source: PathBuf,

    /// Output directory for generated files (relative to working directory).
    #[arg(short, long, default_value = "./types")]
    output: PathBuf,

    /// Output format (typescript or jsdoc).
    #[arg(short, long, value_enum, default_value = "typescript")]
    format: OutputFormat,

    /// Types to export (format: TypeName:path/to/file.rs).
    /// Can be specified multiple times.
    #[arg(short, long = "types")]
    types: Vec<String>,

    /// Generate an index.ts file that re-exports all types (TypeScript only).
    #[arg(long, default_value = "false")]
    index: bool,
}

/// Parsed type specification.
struct TypeSpec {
    name: String,
    path: String,
}

impl TypeSpec {
    fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() == 2 {
            Some(TypeSpec {
                name: parts[0].to_owned(),
                path: parts[1].to_owned(),
            })
        } else {
            None
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Change to working directory if specified
    if let Some(dir) = &cli.dir {
        if let Err(e) = std::env::set_current_dir(dir) {
            eprintln!(
                "Error: failed to change to directory '{}': {e}",
                dir.display()
            );
            return ExitCode::FAILURE;
        }
    }

    // Validate source directory
    if !cli.source.exists() {
        eprintln!(
            "Error: source directory does not exist: {}",
            cli.source.display()
        );
        return ExitCode::FAILURE;
    }

    if !cli.source.is_dir() {
        eprintln!(
            "Error: source path is not a directory: {}",
            cli.source.display()
        );
        return ExitCode::FAILURE;
    }

    // Parse type specifications
    let type_specs: Vec<TypeSpec> = cli.types.iter()
        .filter_map(|s| {
            let spec = TypeSpec::parse(s);
            if spec.is_none() {
                eprintln!("Warning: invalid type specification '{s}', expected format 'TypeName:path/to/file.rs'");
            }
            spec
        })
        .collect();

    if type_specs.is_empty() {
        eprintln!("Error: no valid type specifications provided");
        eprintln!("Usage: --types \"AuthUser:repository/user.rs\"");
        return ExitCode::FAILURE;
    }

    // Create output directory
    if let Err(e) = fs::create_dir_all(&cli.output) {
        eprintln!("Error: failed to create output directory: {e}");
        return ExitCode::FAILURE;
    }

    // Determine file extension based on format
    let extension = match cli.format {
        OutputFormat::Typescript => "ts",
        OutputFormat::Jsdoc => "js",
    };

    // Process each type
    let mut generated_types = Vec::new();
    let mut had_errors = false;

    for spec in &type_specs {
        print!("Generating {}... ", spec.name);

        match parser::parse_type(&cli.source, &spec.path, &spec.name) {
            Ok(def) => {
                let code = match cli.format {
                    OutputFormat::Typescript => typescript::generate_typescript(&def),
                    OutputFormat::Jsdoc => jsdoc::generate_jsdoc(&def),
                };
                let output_path = cli.output.join(format!("{}.{extension}", spec.name));

                match fs::write(&output_path, &code) {
                    Ok(()) => {
                        println!("OK");
                        generated_types.push(spec.name.clone());
                    }
                    Err(e) => {
                        println!("FAILED");
                        eprintln!("  Error writing file: {e}");
                        had_errors = true;
                    }
                }
            }
            Err(e) => {
                println!("FAILED");
                eprintln!("  Error: {e}");
                had_errors = true;
            }
        }
    }

    // Generate index.ts (only for TypeScript)
    if cli.index && !generated_types.is_empty() && matches!(cli.format, OutputFormat::Typescript) {
        let index_content = typescript::generate_index(&generated_types);
        let index_path = cli.output.join("index.ts");

        match fs::write(&index_path, &index_content) {
            Ok(()) => {
                println!("Generated index.ts");
            }
            Err(e) => {
                eprintln!("Error writing index.ts: {e}");
                had_errors = true;
            }
        }
    }

    // Summary
    println!();
    println!(
        "Generated {} type(s) in {}",
        generated_types.len(),
        cli.output.display()
    );

    if had_errors {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
