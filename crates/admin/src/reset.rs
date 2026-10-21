use std::path::{Path, PathBuf};

use clap::Args;
use bichon_core::{
    admin::meta::{find_admin, open_database, update_admin_password, update_admin_password_hash},
    users::hash_login_password,
    utils::encrypt::internal_decrypt_string,
};
use console::{style, Emoji};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};

#[derive(Args, Debug)]
pub struct ResetPasswordArgs {
    /// Absolute Bichon root directory containing the `memdb` directory.
    #[arg(long, value_name = "DIR")]
    pub root: PathBuf,
    /// Root-only file containing the new password. The password is never an
    /// argument and is never printed.
    #[arg(long, value_name = "FILE")]
    pub password_file: PathBuf,
}

fn read_reset_password(path: &Path) -> Result<String, &'static str> {
    if !path.is_absolute() {
        return Err("password file path must be absolute");
    }
    let metadata = std::fs::metadata(path).map_err(|_| "password file is unavailable")?;
    if !metadata.is_file() {
        return Err("password file is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("password file must not be group- or world-readable");
        }
    }
    let password = std::fs::read_to_string(path).map_err(|_| "password file cannot be read")?;
    let password = password.trim_end_matches(['\r', '\n']).to_owned();
    if password.is_empty() {
        return Err("password file is empty");
    }
    Ok(password)
}

fn reset_password_from_file(args: &ResetPasswordArgs) -> Result<(), &'static str> {
    if !args.root.is_absolute() {
        return Err("root path must be absolute");
    }
    let memdb = args.root.join("memdb");
    if !memdb.is_dir() {
        return Err("root path does not contain a memdb directory");
    }
    let password = read_reset_password(&args.password_file)?;
    let database = open_database(&memdb).map_err(|_| "failed to open database")?;
    if find_admin(&database)
        .map_err(|_| "failed to query administrator")?
        .is_none()
    {
        return Err("default administrator was not found");
    }
    let password_hash = hash_login_password(&password).map_err(|_| "failed to hash password")?;
    // Keep the plaintext only until hashing has completed, then let it drop
    // before the database write. The update helper clones the complete record
    // and replaces only the password field.
    drop(password);
    update_admin_password_hash(&database, password_hash)
        .map_err(|_| "failed to update administrator password")
}

pub fn run_noninteractive(args: ResetPasswordArgs) -> i32 {
    match reset_password_from_file(&args) {
        Ok(()) => {
            println!("Administrator password updated.");
            0
        }
        Err(message) => {
            eprintln!("Password reset failed: {message}.");
            1
        }
    }
}

fn validate_existing_password(encrypted: &str, encryption_key: &str) -> bool {
    // Argon2 hashes are already one-way and cannot validate the legacy
    // encryption key. This preserves the previous behavior for those users.
    encrypted.starts_with("$argon2id$")
        || internal_decrypt_string(encryption_key, encrypted).is_ok()
}

pub fn handle_reset_password(theme: &ColorfulTheme) {
    let root_dir_str: String = Input::with_theme(theme)
        .with_prompt("Enter the absolute path for 'bichon_root_dir'")
        .validate_with(|input: &String| -> Result<(), &str> {
            let path = Path::new(input);
            if !path.is_absolute() {
                return Err("Path must be absolute.");
            }
            if !path.exists() {
                return Err("Directory does not exist.");
            }
            let memdb_dir = path.join("memdb");
            if !memdb_dir.exists() || !memdb_dir.is_dir() {
                return Err("Invalid directory: 'memdb' data directory not found.");
            }
            Ok(())
        })
        .interact_text()
        .unwrap();

    let root_path = PathBuf::from(&root_dir_str);
    let database = open_database(&root_path.join("memdb")).unwrap_or_else(|e| {
        eprintln!(
            "\n{} Failed to open database.",
            style("ERROR:").red().bold()
        );
        eprintln!("Details: {:?}", e);
        std::process::exit(1);
    });

    let admin = find_admin(&database);

    match admin {
        Ok(Some(user)) => {
            println!("\n{}", style("Admin user found:").green().bold());
            println!("----------------------------------------");
            println!("{:<12} : {}", "Username", style(&user.username).cyan());
            println!("{:<12} : {}", "Email", style(&user.email).cyan());
        }
        Ok(None) => {
            println!(
                "\n{}",
                style("ERROR: No admin user found in the database.")
                    .red()
                    .bold()
            );
            println!("Please ensure the system has been initialized correctly.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "\n{} Failed to query admin user.",
                style("ERROR:").red().bold()
            );
            eprintln!("Details: {:?}", e);
            std::process::exit(1);
        }
    }

    let encryption_key = loop {
        let auth_methods = vec![
            "Enter encryption password manually",
            "Read from password file",
        ];
        let method = Select::with_theme(theme)
            .with_prompt("How would you like to provide the database encryption key?")
            .items(&auth_methods)
            .interact()
            .unwrap();

        let raw_key = if method == 0 {
            Password::with_theme(theme)
                .with_prompt("Enter Encryption Password")
                .interact()
                .unwrap()
        } else {
            let file_path: String = Input::with_theme(theme)
                .with_prompt("Enter path to encryption password file")
                .interact_text()
                .unwrap();

            match std::fs::read_to_string(&file_path) {
                Ok(content) => content.trim().to_string(),
                Err(e) => {
                    println!("{}: {}", style("Failed to read file").red(), e);
                    continue;
                }
            }
        };

        if raw_key.is_empty() {
            println!("{}", style("Key cannot be empty.").red());
            continue;
        }

        // Never echo the encryption key. This command is commonly run in a
        // terminal or captured by a support transcript, so printing the key
        // would turn an otherwise protected handoff into a credential leak.
        let prompt_message = format!(
            "Encryption key loaded securely.\n\n  \
                {}: This key must match the database encryption key used by the server.\n  \
                It corresponds to these settings in your service:\n    \
                - Arguments: {} or {}\n    \
                - Envs:      {} or {}\n\n  \
                Do you want to continue?",
            style("IMPORTANT").yellow().bold(),
            style("--bichon_encrypt_password").italic(),
            style("--bichon_encrypt_password_file").italic(),
            style("BICHON_ENCRYPT_PASSWORD").green(),
            style("BICHON_ENCRYPT_PASSWORD_FILE").green()
        );

        if Confirm::with_theme(theme)
            .with_prompt(prompt_message)
            .default(true)
            .interact()
            .unwrap()
        {
            break raw_key;
        }
    };

    let admin = find_admin(&database);

    match admin {
        Ok(Some(user)) => {
            println!("----------------------------------------");
            println!("{:<12} : {}", "Username", style(&user.username).cyan());
            println!("{:<12} : {}", "Email", style(&user.email).cyan());

            // Never print the current password. Besides exposing a credential
            // in the terminal, this command is often captured in support
            // transcripts. Validate the legacy encrypted value without
            // retaining or displaying its decrypted contents.
            let pwd_display = match &user.password {
                Some(p) if p.starts_with("$argon2id$") => style("(password hash present - hidden)")
                    .dim()
                    .italic()
                    .to_string(),
                Some(encrypted) => {
                    if !validate_existing_password(encrypted, &encryption_key) {
                        println!(
                            "\n{}",
                            style("ERROR: Encryption key validation failed")
                                .red()
                                .bold()
                        );
                        println!(
                            "{}",
                            style("The provided encryption key is incorrect or invalid for this database.").yellow()
                        );
                        std::process::exit(1);
                    }
                    style("(password present - hidden)")
                        .dim()
                        .italic()
                        .to_string()
                }
                None => style("None (No password set)").dim().italic().to_string(),
            };

            println!("{:<12} : {}", "Password", pwd_display);
            println!("----------------------------------------");

            if !dialoguer::Confirm::with_theme(theme)
                .with_prompt(format!(
                    "Do you want to reset the password for '{}'?",
                    user.username
                ))
                .interact()
                .unwrap()
            {
                println!("Operation cancelled.");
                return;
            }
        }
        Ok(None) => {
            println!(
                "\n{}",
                style("ERROR: No admin user found in the database.")
                    .red()
                    .bold()
            );
            println!("Please ensure the system has been initialized correctly.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "\n{} Failed to query admin user.",
                style("ERROR:").red().bold()
            );
            eprintln!("Details: {:?}", e);
            std::process::exit(1);
        }
    }

    println!(
        "\n{}",
        style("TARGET: Reset password for user 'admin'")
            .yellow()
            .bold()
    );

    let new_login_password = Password::with_theme(theme)
        .with_prompt("Enter new Admin Login Password")
        .with_confirmation("Repeat password to confirm", "Passwords do not match!")
        .interact()
        .unwrap();

    if !Confirm::with_theme(theme)
        .with_prompt("Proceed with database update?")
        .interact()
        .unwrap()
    {
        return;
    }

    println!("\n{} {}", style("⌛").yellow(), "Updating database...");

    match update_admin_password(&database, new_login_password, &encryption_key) {
        Ok(_) => {
            println!(
                "\n{} {}",
                Emoji("✨", "*"),
                style("Success! Admin password has been updated.")
                    .green()
                    .bold()
            );
            println!(
                "{}",
                style("You can now log in with the new password.").dim()
            );
        }
        Err(e) => {
            println!(
                "\n{}",
                style("ERROR: Failed to update database").red().bold()
            );
            eprintln!(
                "{} Could not save the new password to the database.",
                style("➔").cyan()
            );
            eprintln!("\nDetails: {:?}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{reset_password_from_file, validate_existing_password, ResetPasswordArgs};
    use bichon_core::{
        database::MemDbModel,
        users::{verify_login_password, UserModel, BichonUserV2, DEFAULT_ADMIN_USER_ID},
        utils::encrypt::internal_encrypt_string,
    };
    use bichon_memdb::{Durability, MemDb};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn legacy_password_rejects_wrong_encryption_key() {
        let encrypted = internal_encrypt_string("correct-key", "old-password").unwrap();
        assert!(!validate_existing_password(&encrypted, "wrong-key"));
    }

    #[test]
    fn legacy_password_accepts_correct_encryption_key() {
        let encrypted = internal_encrypt_string("correct-key", "old-password").unwrap();
        assert!(validate_existing_password(&encrypted, "correct-key"));
    }

    #[test]
    fn argon2_password_skips_legacy_key_validation() {
        assert!(validate_existing_password(
            "$argon2id$v=19$test",
            "irrelevant"
        ));
    }

    #[test]
    fn file_reset_hashes_password_and_preserves_admin_fields() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("bichon");
        let memdb = root.join("memdb");
        fs::create_dir_all(&memdb).unwrap();
        let before = BichonUserV2 {
            id: DEFAULT_ADMIN_USER_ID,
            username: "admin".into(),
            email: "admin@example.invalid".into(),
            description: Some("preserve this".into()),
            global_roles: vec![42],
            ..Default::default()
        };
        {
            let db = MemDb::open_with(&memdb, Durability::Full).unwrap();
            db.collection(UserModel::collection())
                .upsert(before.key(), &before)
                .unwrap();
        }

        let password_file = temp.path().join("new-password");
        fs::write(&password_file, "new-secret\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&password_file, fs::Permissions::from_mode(0o600)).unwrap();
        }

        reset_password_from_file(&ResetPasswordArgs {
            root: root.clone(),
            password_file,
        })
        .unwrap();

        let db = MemDb::open_with(&memdb, Durability::Full).unwrap();
        let after: UserModel = db
            .collection(UserModel::collection())
            .get_required(&DEFAULT_ADMIN_USER_ID.to_string())
            .unwrap();
        assert_eq!(after.username, before.username);
        assert_eq!(after.email, before.email);
        assert_eq!(after.description, before.description);
        assert_eq!(after.global_roles, before.global_roles);
        let stored = after.password.as_deref().unwrap();
        assert!(verify_login_password(stored, "new-secret"));
        assert!(!verify_login_password(stored, "wrong-secret"));
        assert!(!stored.contains("new-secret"));
    }

    #[test]
    fn file_reset_rejects_group_readable_password_file() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("bichon");
        fs::create_dir_all(root.join("memdb")).unwrap();
        let password_file = temp.path().join("new-password");
        fs::write(&password_file, "secret").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&password_file, fs::Permissions::from_mode(0o640)).unwrap();
            let error = reset_password_from_file(&ResetPasswordArgs {
                root,
                password_file,
            })
            .unwrap_err();
            assert_eq!(error, "password file must not be group- or world-readable");
        }
    }
}
