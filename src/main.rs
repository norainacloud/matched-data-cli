#![warn(rust_2018_idioms)]

mod matched_data;

use crate::matched_data::generate_key_pair;
use clap::{ArgEnum, Parser};
use hpke::Serializable;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{stdin, stdout, Read, Write};
use std::{fs, str};

#[derive(Parser)]
#[clap(about, author, version)]
struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(ArgEnum, Clone)]
enum KeyPairOutputFormat {
    Json,
}

#[derive(Parser)]
struct GenerateKeyPairOptions {
    #[clap(
        arg_enum,
        short,
        long,
        value_name = "format",
        help = "Output format of key pair",
        default_value = "json"
    )]
    output_format: KeyPairOutputFormat,
}

#[derive(ArgEnum, Clone)]
enum DecryptOutputFormat {
    Raw,
    Utf8Lossy,
}

#[derive(ArgEnum, Clone)]
enum DecryptInputFormat {
    /// A single base64 encoded encrypted matched data payload
    Blob,
    /// A JSON list of firewall events, as exported from the Cloudflare dashboard
    FirewallEventsJson,
    /// Firewall events as JSON Lines, one event per line
    FirewallEventsJsonl,
}

#[derive(Parser)]
struct DecryptOptions {
    #[clap(help = "File containing the input, or '-' to read from stdin")]
    matched_data_filename: String,

    #[clap(
        short = 'k',
        long,
        help = "File containing the base64 encoded private key"
    )]
    private_key_filename: String,

    #[clap(
        arg_enum,
        short,
        long,
        value_name = "format",
        help = "Output format of matched data (ignored for the firewall-events-json input format)",
        default_value = "utf8-lossy"
    )]
    output_format: DecryptOutputFormat,

    #[clap(
        arg_enum,
        short,
        long,
        value_name = "format",
        help = "Input format of matched data",
        default_value = "blob"
    )]
    input_format: DecryptInputFormat,
}

#[derive(Parser)]
enum Command {
    /// Generates a public-private key pair
    GenerateKeyPair(GenerateKeyPairOptions),

    /// Decrypts data
    Decrypt(DecryptOptions),
}

#[derive(Serialize, Deserialize)]
struct KeyPair {
    private_key: String,
    public_key: String,
}

const TRUNCATED: &str = "truncated";
const ENCRYPTED_MATCHED_DATA_KEY: &str = "encrypted_matched_data";
const MATCHED_DATA_KEY: &str = "matched_data";

// Decrypts a base64 encoded encrypted matched data payload
fn decrypt_matched_data(
    matched_data_base64: &str,
    private_key_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if matched_data_base64 == TRUNCATED {
        return Err(
            "The payload match for this event is unavailable because it was too large.".to_string(),
        );
    };

    let encrypted_matched_data_bytes = radix64::STD
        .decode(matched_data_base64)
        .map_err(|_| "Provided matched data is not base64 encoded")?;

    macro_rules! decrypt {
        ($modname:ident) => {{
            use $modname::{decrypt_data, deserialize_encrypted_data, get_private_key_from_bytes};

            let private_key = get_private_key_from_bytes(private_key_bytes)
                .map_err(|_| "Provided private key is invalid")?;

            let encrypted_matched_data = deserialize_encrypted_data(&encrypted_matched_data_bytes)
                .map_err(|_| "Provided matched data is invalid")?;

            // Decrypt matched data
            decrypt_data(&encrypted_matched_data, &private_key)
                .map_err(|_| "Failed to decrypt matched data")?
        }};
    }

    // Get encryption version
    let encryption_format_version = *encrypted_matched_data_bytes
        .first()
        .ok_or("Provided matched data is empty")?;

    let matched_data = match encryption_format_version {
        3 => decrypt!(matched_data),
        _ => {
            let available_versions = "'3'";

            return Err(format!(
                "Encryption format not supported, expected {}, got '{}'",
                available_versions, encryption_format_version
            ));
        }
    };

    Ok(matched_data)
}

// Decrypts every encrypted matched data payload found in a firewall event, in place.
//
// Both metadata shapes are recognised, wherever they appear in the event:
//   `{"key": "encrypted_matched_data", "value": "<payload>"}`
//   `{"encrypted_matched_data": "<payload>"}`
// Each is rewritten to hold the decrypted payload under `matched_data`, keeping the
// surrounding fields and their order. Events without a payload are left untouched, and
// failures are reported on stderr so that a single bad event does not discard the rest
// of the output.
fn decrypt_event_matched_data(event: &mut Value, private_key_bytes: &[u8]) {
    match event {
        Value::Array(events) => {
            for event in events.iter_mut() {
                decrypt_event_matched_data(event, private_key_bytes);
            }
        }
        Value::Object(entry) => {
            // `{"key": "encrypted_matched_data", "value": "<payload>"}`
            if entry.get("key").and_then(Value::as_str) == Some(ENCRYPTED_MATCHED_DATA_KEY) {
                if let Some(matched_data) = entry
                    .get("value")
                    .and_then(Value::as_str)
                    .and_then(|payload| decrypt_event_payload(payload, private_key_bytes))
                {
                    entry["key"] = Value::from(MATCHED_DATA_KEY);
                    entry["value"] = matched_data;
                }

                return;
            }

            // `{"encrypted_matched_data": "<payload>"}`
            if let Some(matched_data) = entry
                .get(ENCRYPTED_MATCHED_DATA_KEY)
                .and_then(Value::as_str)
                .and_then(|payload| decrypt_event_payload(payload, private_key_bytes))
            {
                // Rebuild the entry rather than removing and inserting, to keep field order
                let mut matched_data = Some(matched_data);
                *entry = std::mem::take(entry)
                    .into_iter()
                    .map(|(key, value)| {
                        if key == ENCRYPTED_MATCHED_DATA_KEY {
                            if let Some(matched_data) = matched_data.take() {
                                return (MATCHED_DATA_KEY.to_string(), matched_data);
                            }
                        }

                        (key, value)
                    })
                    .collect();
            }

            for (_, value) in entry.iter_mut() {
                decrypt_event_matched_data(value, private_key_bytes);
            }
        }
        _ => {}
    }
}

// Decrypts a single payload of an event, reporting failures on stderr
fn decrypt_event_payload(payload: &str, private_key_bytes: &[u8]) -> Option<Value> {
    match decrypt_matched_data(payload.trim_end(), private_key_bytes) {
        Ok(matched_data) => Some(Value::from(
            String::from_utf8_lossy(&matched_data).into_owned(),
        )),
        Err(error) => {
            eprintln!("Failed to decrypt matched data of event: {}", error);
            None
        }
    }
}

fn run(options: Options) -> Result<(), String> {
    match options.command {
        Command::GenerateKeyPair(command) => {
            // Generate key pair
            let (private_key, public_key) = generate_key_pair();

            let key_pair = KeyPair {
                private_key: radix64::STD.encode(&private_key.to_bytes()),
                public_key: radix64::STD.encode(&public_key.to_bytes()),
            };

            match command.output_format {
                KeyPairOutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&key_pair).expect("Failed to output key pair")
                    );
                }
            }
        }
        Command::Decrypt(command) => {
            // Validate and construct private key from input
            let private_key_base64 = fs::read_to_string(command.private_key_filename)
                .map_err(|_| "Failed to read private key from file")?;

            let private_key_bytes = radix64::STD
                .decode(&private_key_base64.trim_end())
                .map_err(|_| "Provided private key is not base64 encoded")?;

            // Read input, either from a file or from stdin
            let input = if command.matched_data_filename == "-" {
                let mut buffer = String::new();
                stdin()
                    .read_to_string(&mut buffer)
                    .map_err(|_| "Failed to read matched data from stdin")?;
                buffer
            } else {
                fs::read_to_string(command.matched_data_filename)
                    .map_err(|_| "Failed to read matched data from file")?
            };

            match command.input_format {
                DecryptInputFormat::Blob => {
                    let matched_data = decrypt_matched_data(input.trim_end(), &private_key_bytes)?;

                    match command.output_format {
                        DecryptOutputFormat::Raw => {
                            let mut out = stdout();
                            out.write_all(&matched_data)
                                .map_err(|_| "Failed to output matched data")?;
                            out.flush().expect("Failed to flush stdout");
                        }
                        DecryptOutputFormat::Utf8Lossy => {
                            println!("{}", String::from_utf8_lossy(&matched_data));
                        }
                    }
                }
                DecryptInputFormat::FirewallEventsJson => {
                    let mut events: Value = serde_json::from_str(&input)
                        .map_err(|_| "Provided firewall events are not valid JSON")?;

                    if !events.is_array() && !events.is_object() {
                        return Err(
                            "Expected a list of firewall events or a single firewall event"
                                .to_string(),
                        );
                    }

                    decrypt_event_matched_data(&mut events, &private_key_bytes);

                    println!(
                        "{}",
                        serde_json::to_string_pretty(&events)
                            .map_err(|_| "Failed to output firewall events")?
                    );
                }
                DecryptInputFormat::FirewallEventsJsonl => {
                    let mut out = stdout();

                    for (number, line) in input.lines().enumerate() {
                        // Blank lines carry no event, keep going
                        if line.trim().is_empty() {
                            continue;
                        }

                        let mut event: Value = serde_json::from_str(line).map_err(|_| {
                            format!("Line {} is not a valid JSON firewall event", number + 1)
                        })?;

                        decrypt_event_matched_data(&mut event, &private_key_bytes);

                        writeln!(
                            out,
                            "{}",
                            serde_json::to_string(&event)
                                .map_err(|_| "Failed to output firewall events")?
                        )
                        .map_err(|_| "Failed to output firewall events")?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), String> {
    run(Options::parse())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::Command;
    use assert_fs::prelude::*;

    #[test]
    fn test_generate_key_pair() {
        let mut cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd.args(&["generate-key-pair"]).output().unwrap();

        let key_pair: KeyPair =
            serde_json::from_str(std::str::from_utf8(&out.stdout).unwrap()).unwrap();

        radix64::STD.decode(&key_pair.private_key).unwrap();
        radix64::STD.decode(&key_pair.public_key).unwrap();
    }

    #[test]
    fn test_decrypt() {
        let matched_data = "test matched data";
        // Encrypted with public key:
        // Ycig/Zr/pZmklmFUN99nr+taURlYItL91g+NcHGYpB8=
        let encrypted_matched_data = "AzTY6FHajXYXuDMUte82wrd+1n5CEHPoydYiyd3FMg5IEQAAAAAAAAA0lOhGXBclw8pWU5jbbYuepSIJN5JohTtZekLliJBlVWk=";
        let private_key = "uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=";

        let temp_dir = assert_fs::TempDir::new().unwrap();
        let encrypted_matched_data_file = temp_dir.child("encrypted_matched_data.txt");
        encrypted_matched_data_file
            .write_str(encrypted_matched_data)
            .unwrap();
        let private_key_file = temp_dir.child("private_key.txt");
        private_key_file.write_str(private_key).unwrap();

        // Matched data key in file
        let mut cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-k",
                private_key_file.path().to_str().unwrap(),
                encrypted_matched_data_file.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();

        assert_eq!(
            format!("{}\n", matched_data),
            str::from_utf8(&out.stdout).unwrap()
        );

        // Matched data key in stdin
        cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-k",
                private_key_file.path().to_str().unwrap(),
                "-",
            ])
            .write_stdin(encrypted_matched_data)
            .output()
            .unwrap();

        assert_eq!(
            format!("{}\n", matched_data),
            str::from_utf8(&out.stdout).unwrap()
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_decrypt_truncation() {
        let private_key = "uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=";

        let temp_dir = assert_fs::TempDir::new().unwrap();
        let encrypted_matched_data_file = temp_dir.child("encrypted_matched_data.txt");
        encrypted_matched_data_file.write_str(TRUNCATED).unwrap();
        let private_key_file = temp_dir.child("private_key.txt");
        private_key_file.write_str(private_key).unwrap();
        let mut cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-k",
                private_key_file.path().to_str().unwrap(),
                encrypted_matched_data_file.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(
            format!("{}\n", "Error: \"The payload match for this event is unavailable because it was too large.\""),
            str::from_utf8(&out.stderr).unwrap()
        );
        temp_dir.close().unwrap();
    }
    #[test]
    fn test_decrypt_firewall_events_json() {
        let matched_data = "test matched data";
        // Encrypted with public key:
        // Ycig/Zr/pZmklmFUN99nr+taURlYItL91g+NcHGYpB8=
        let encrypted_matched_data = "AzTY6FHajXYXuDMUte82wrd+1n5CEHPoydYiyd3FMg5IEQAAAAAAAAA0lOhGXBclw8pWU5jbbYuepSIJN5JohTtZekLliJBlVWk=";
        let private_key = "uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=";

        let events = serde_json::json!([
            {
                "ruleId": "key-value-metadata",
                "metadata": [
                    { "key": "ruleset_version", "value": "87" },
                    { "key": "encrypted_matched_data", "value": encrypted_matched_data },
                ],
            },
            {
                "ruleId": "object-metadata",
                "metadata": {
                    "ruleset_version": "87",
                    "encrypted_matched_data": encrypted_matched_data,
                    "score_total": "40",
                },
            },
            {
                "ruleId": "without-matched-data",
                "metadata": [{ "key": "ruleset_version", "value": "87" }],
            },
            {
                "ruleId": "truncated-matched-data",
                "metadata": [{ "key": "encrypted_matched_data", "value": TRUNCATED }],
            },
            { "ruleId": "without-metadata" },
        ]);

        let temp_dir = assert_fs::TempDir::new().unwrap();
        let events_file = temp_dir.child("events.json");
        events_file.write_str(&events.to_string()).unwrap();
        let private_key_file = temp_dir.child("private_key.txt");
        private_key_file.write_str(private_key).unwrap();

        let mut cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-k",
                private_key_file.path().to_str().unwrap(),
                "-i",
                "firewall-events-json",
                events_file.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();

        let decrypted: Value = serde_json::from_slice(&out.stdout).unwrap();

        // The encrypted entry is replaced by the decrypted one, in place
        assert_eq!(
            decrypted[0]["metadata"],
            serde_json::json!([
                { "key": "ruleset_version", "value": "87" },
                { "key": "matched_data", "value": matched_data },
            ])
        );

        // The same goes for metadata held as an object, whose field order is kept
        assert_eq!(
            serde_json::to_string(&decrypted[1]["metadata"]).unwrap(),
            serde_json::to_string(&serde_json::json!({
                "ruleset_version": "87",
                "matched_data": matched_data,
                "score_total": "40",
            }))
            .unwrap()
        );

        // Events without matched data are passed through untouched
        assert_eq!(decrypted[2], events[2]);
        assert_eq!(decrypted[4], events[4]);

        // Truncated matched data is kept as is and reported on stderr
        assert_eq!(decrypted[3], events[3]);
        assert!(str::from_utf8(&out.stderr)
            .unwrap()
            .contains("it was too large"));

        // Reading from stdin works too
        cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-k",
                private_key_file.path().to_str().unwrap(),
                "-i",
                "firewall-events-json",
                "-",
            ])
            .write_stdin(events.to_string())
            .output()
            .unwrap();

        assert_eq!(
            decrypted,
            serde_json::from_slice::<Value>(&out.stdout).unwrap()
        );

        temp_dir.close().unwrap();
    }

    #[test]
    fn test_decrypt_firewall_events_jsonl() {
        let matched_data = "test matched data";
        // Encrypted with public key:
        // Ycig/Zr/pZmklmFUN99nr+taURlYItL91g+NcHGYpB8=
        let encrypted_matched_data = "AzTY6FHajXYXuDMUte82wrd+1n5CEHPoydYiyd3FMg5IEQAAAAAAAAA0lOhGXBclw8pWU5jbbYuepSIJN5JohTtZekLliJBlVWk=";
        let private_key = "uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=";

        let events = [
            serde_json::json!({
                "ruleId": "key-value-metadata",
                "metadata": [{ "key": "encrypted_matched_data", "value": encrypted_matched_data }],
            }),
            serde_json::json!({
                "ruleId": "object-metadata",
                "metadata": { "encrypted_matched_data": encrypted_matched_data },
            }),
            serde_json::json!({ "ruleId": "without-matched-data" }),
        ];

        // Blank lines are skipped
        let input = format!("{}\n\n{}\n{}\n", events[0], events[1], events[2]);

        let temp_dir = assert_fs::TempDir::new().unwrap();
        let events_file = temp_dir.child("events.jsonl");
        events_file.write_str(&input).unwrap();
        let private_key_file = temp_dir.child("private_key.txt");
        private_key_file.write_str(private_key).unwrap();

        let mut cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-k",
                private_key_file.path().to_str().unwrap(),
                "-i",
                "firewall-events-jsonl",
                events_file.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();

        // One event per line, in the order they came in
        let decrypted: Vec<Value> = str::from_utf8(&out.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(
            decrypted,
            vec![
                serde_json::json!({
                    "ruleId": "key-value-metadata",
                    "metadata": [{ "key": "matched_data", "value": matched_data }],
                }),
                serde_json::json!({
                    "ruleId": "object-metadata",
                    "metadata": { "matched_data": matched_data },
                }),
                events[2].clone(),
            ]
        );

        // A line that is not valid JSON is reported, pointing at the line
        cmd = Command::cargo_bin("matched-data-cli").unwrap();
        let out = cmd
            .args(&[
                "decrypt",
                "-k",
                private_key_file.path().to_str().unwrap(),
                "-i",
                "firewall-events-jsonl",
                "-",
            ])
            .write_stdin(format!("{}\nnot json\n", events[0]))
            .output()
            .unwrap();

        assert!(str::from_utf8(&out.stderr)
            .unwrap()
            .contains("Line 2 is not a valid JSON firewall event"));

        temp_dir.close().unwrap();
    }
}
