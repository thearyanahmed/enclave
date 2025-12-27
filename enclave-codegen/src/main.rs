//! Enclave TypeScript code generator CLI.
//!
//! Generates TypeScript type definitions from Rust source files.
//!
//! # Usage
//!
//! ```bash
//! enclave-codegen \
//!     --source ./src \
//!     --output ./types \
//!     --types "AuthUser:repository/user.rs" \
//!     --types "AuthError:lib.rs"
//! ```

use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

mod parser;
mod typescript;

/// TypeScript code generator for Rust types.
#[derive(Parser, Debug)]
#[command(name = "enclave-codegen")]
#[command(version, about = "Generate TypeScript types from Rust source files")]
struct Cli {
    /// Working directory (changes to this directory before running).
    #[arg(short = 'C', long = "dir")]
    dir: Option<PathBuf>,

    /// Path to the Rust source directory (relative to working directory).
    #[arg(short, long)]
    source: PathBuf,

    /// Output directory for TypeScript files (relative to working directory).
    #[arg(short, long, default_value = "./types")]
    output: PathBuf,

    /// Types to export (format: TypeName:path/to/file.rs).
    /// Can be specified multiple times.
    #[arg(short, long = "types")]
    types: Vec<String>,

    /// Generate an index.ts file that re-exports all types.
    #[arg(long, default_value = "true")]
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
            eprintln!("Error: failed to change to directory '{}': {e}", dir.display());
            return ExitCode::FAILURE;
        }
    }

    // Validate source directory
    if !cli.source.exists() {
        eprintln!("Error: source directory does not exist: {}", cli.source.display());
        return ExitCode::FAILURE;
    }

    if !cli.source.is_dir() {
        eprintln!("Error: source path is not a directory: {}", cli.source.display());
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

    // Process each type
    let mut generated_types = Vec::new();
    let mut had_errors = false;

    for spec in &type_specs {
        print!("Generating {}... ", spec.name);

        match parser::parse_type(&cli.source, &spec.path, &spec.name) {
            Ok(def) => {
                let ts_code = typescript::generate_typescript(&def);
                let output_path = cli.output.join(format!("{}.ts", spec.name));

                match fs::write(&output_path, &ts_code) {
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

    // Generate index.ts
    if cli.index && !generated_types.is_empty() {
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
    println!("Generated {} type(s) in {}", generated_types.len(), cli.output.display());

    if had_errors {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
