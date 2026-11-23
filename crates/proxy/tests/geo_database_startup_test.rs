//! A geo filter whose database cannot be opened stops startup.
//!
//! The filter is only registered once its database is open. A filter that
//! failed to register used to be logged and skipped, and startup went on
//! without it. Startup now fails instead, and says which filter and which
//! file. `zentinel test` and `zentinel validate` open the same databases, so a
//! configuration that passes them does not stop startup on one.
//!
//! An IP2Location file that was cut short opens, as only its header is read
//! then, and the lookups that read what is missing fail. A file shorter than
//! the size its header records is now refused, and opening a database includes
//! a few trial lookups that find other damage in what they read, so such a
//! file is refused like a missing one.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A port the OS had free a moment ago. The proxy is expected to exit before it
/// binds anything, so a clash would not change the outcome.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local address")
        .port()
}

/// A configuration with two geo filters whose databases do not exist, written
/// into `dir`. Returns its path, the listener port, and the two database paths.
fn write_config(dir: &Path) -> (PathBuf, u16, [PathBuf; 2]) {
    let databases = [
        dir.join("missing-country.mmdb"),
        dir.join("missing-city.mmdb"),
    ];
    let config = dir.join("zentinel.kdl");
    let listener_port = free_port();
    std::fs::write(
        &config,
        format!(
            r#"
system {{ worker-threads 1 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{listener_port}"
        protocol "http"
    }}
}}
filters {{
    filter "region-block" {{
        type "geo"
        database-path "{country}"
        action "block"
        countries "RU" "CN"
    }}
    filter "city-allow" {{
        type "geo"
        database-path "{city}"
        action "allow"
        countries "US"
    }}
}}
routes {{
    route "default" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "region-block"
    }}
}}
upstreams {{
    upstream "backend" {{
        // Never connected to: the proxy is not expected to get this far.
        target "127.0.0.1:{backend_port}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
            country = databases[0].display(),
            city = databases[1].display(),
            backend_port = free_port(),
        ),
    )
    .unwrap();
    (config, listener_port, databases)
}

/// What is expected in the output when databases are missing: both filters and
/// both files, and the filters in the order of their ids.
fn assert_names_both_filters(output: &str, databases: &[PathBuf; 2]) {
    for expected in [
        "region-block",
        "city-allow",
        &databases[0].display().to_string(),
        &databases[1].display().to_string(),
    ] {
        assert!(
            output.contains(expected),
            "the error does not mention {expected}; {output}"
        );
    }
    let listing = &output[output
        .find("cannot be used")
        .expect("the error lists the filters")..];
    assert!(
        listing.find("city-allow") < listing.find("region-block"),
        "the filters are not listed in the order of their ids; {output}"
    );
}

/// Run `zentinel <args>`, which is expected to finish on its own, and return
/// whether it succeeded with everything it printed.
fn run_to_completion(args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        output.status.success(),
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn a_geo_filter_whose_database_is_missing_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    let (config, listener_port, databases) = write_config(dir.path());

    let stdout_path = dir.path().join("stdout.log");
    let stderr_path = dir.path().join("stderr.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("-c")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout_path).unwrap())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();

    // Wait for the process to exit, or for the listener to come up, which
    // means startup went on without the filter.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut exited = false;
    let mut listening = false;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        if TcpStream::connect(("127.0.0.1", listener_port)).is_ok() {
            listening = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // A no-op for a process that has exited; `wait` then returns its status.
    let _ = child.kill();
    let status = child.wait().unwrap();

    let output = format!(
        "stdout:\n{}\nstderr:\n{}",
        std::fs::read_to_string(&stdout_path).unwrap_or_default(),
        std::fs::read_to_string(&stderr_path).unwrap_or_default()
    );

    assert!(
        !listening,
        "the proxy started listening although the databases of its geo filters are missing; {output}"
    );
    assert!(
        exited,
        "the proxy neither exited nor listened within 30s; {output}"
    );
    assert!(
        !status.success(),
        "the proxy exited with {status} although a geo database is missing; {output}"
    );
    assert_names_both_filters(&output, &databases);
}

#[test]
fn test_fails_for_a_geo_filter_whose_database_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _, databases) = write_config(dir.path());

    let (success, output) = run_to_completion(&["test", "-c", config.to_str().unwrap()]);

    assert!(
        !success,
        "`zentinel test` passed although a geo database is missing; {output}"
    );
    assert_names_both_filters(&output, &databases);
}

#[test]
fn validate_fails_for_a_geo_filter_whose_database_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _, databases) = write_config(dir.path());

    let (success, output) = run_to_completion(&[
        "validate",
        "-c",
        config.to_str().unwrap(),
        "--skip-network",
        "--skip-agents",
        "--skip-certs",
    ]);

    assert!(
        !success,
        "`zentinel validate` passed although a geo database is missing; {output}"
    );
    assert_names_both_filters(&output, &databases);
}

// ---------------------------------------------------------------------------
// An IP2Location file that was cut short
// ---------------------------------------------------------------------------

/// An IP2Location DB1 (country only) file with IPv4 rows only: the addresses
/// below 128.0.0.0 are in `first` and the rest in `second`.
///
/// The header is laid out as `ip2location` reads it (`read_header` in
/// `ip2location-0.6.1/src/ip2location/db.rs`); the country strings come after
/// the rows.
fn ip2location_database(first: &str, second: &str) -> Vec<u8> {
    const HEADER_LEN: usize = 64;
    const ROWS: [u32; 3] = [0, 0x8000_0000, u32::MAX];
    let strings = HEADER_LEN + ROWS.len() * 8;

    // A country is its code and its name, each behind its length.
    let mut country_strings = Vec::new();
    let mut positions = Vec::new();
    for code in [first, second] {
        positions.push(u32::try_from(strings + country_strings.len()).unwrap());
        let name = format!("Country {code}");
        country_strings.push(code.len() as u8);
        country_strings.extend_from_slice(code.as_bytes());
        country_strings.push(name.len() as u8);
        country_strings.extend_from_slice(name.as_bytes());
    }

    let mut file = vec![0u8; HEADER_LEN];
    for (i, from) in ROWS.iter().enumerate() {
        file.extend_from_slice(&from.to_le_bytes());
        file.extend_from_slice(&positions[i.min(1)].to_le_bytes());
    }
    file.extend(country_strings);

    file[0] = 1; // database type: DB1
    file[1] = 2; // columns in a row: the address and the country
    file[2..5].copy_from_slice(&[24, 1, 1]); // year, month, day
    file[5..9].copy_from_slice(&2u32.to_le_bytes()); // IPv4 rows
    file[9..13].copy_from_slice(&(HEADER_LEN as u32 + 1).to_le_bytes()); // 1-based
    file[29] = 1; // product code: IP2Location
    let len = u32::try_from(file.len()).unwrap();
    file[31..35].copy_from_slice(&len.to_le_bytes());
    file
}

/// A configuration with one geo filter on `database`, written into `dir`.
fn write_config_for(dir: &Path, database: &Path) -> PathBuf {
    let config = dir.join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{ worker-threads 1 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{listener_port}"
        protocol "http"
    }}
}}
filters {{
    filter "region" {{
        type "geo"
        database-path "{database}"
        countries "RU"
    }}
}}
routes {{
    route "default" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "region"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend_port}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
            database = database.display(),
            listener_port = free_port(),
            backend_port = free_port(),
        ),
    )
    .unwrap();
    config
}

#[test]
fn test_passes_for_a_whole_ip2location_file_and_fails_for_one_cut_short() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("country.BIN");
    let config = write_config_for(dir.path(), &database);
    let whole = ip2location_database("US", "DE");
    let run = || run_to_completion(&["test", "-c", config.to_str().unwrap()]);

    std::fs::write(&database, &whole).unwrap();
    let (success, output) = run();
    assert!(
        success,
        "`zentinel test` failed for a whole IP2Location file; {output}"
    );

    // One byte short of the size its header records.
    std::fs::write(&database, &whole[..whole.len() - 1]).unwrap();
    let (success, output) = run();
    assert!(
        !success,
        "`zentinel test` passed for an IP2Location file that was cut short; {output}"
    );
    for expected in ["region", &database.display().to_string(), "cut short"] {
        assert!(
            output.contains(expected),
            "the error does not mention {expected}; {output}"
        );
    }

    // Cut short, with the size its header records changed to match: the trial
    // lookups find that the end of the file is missing.
    let mut cut = whole[..whole.len() - 1].to_vec();
    let len = u32::try_from(cut.len()).unwrap();
    cut[31..35].copy_from_slice(&len.to_le_bytes());
    std::fs::write(&database, &cut).unwrap();
    let (success, output) = run();
    assert!(
        !success,
        "`zentinel test` passed for an IP2Location file that fails its trial lookups; {output}"
    );
    for expected in ["region", &database.display().to_string(), "trial lookup"] {
        assert!(
            output.contains(expected),
            "the error does not mention {expected}; {output}"
        );
    }
}
