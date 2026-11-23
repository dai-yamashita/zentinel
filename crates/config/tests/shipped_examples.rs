//! Every shipped example configuration must load and validate.
//!
//! The examples are what users copy, so an example that `zentinel test`
//! rejects is worse than no example at all. Nine of them had drifted away
//! from the syntax the parser implements before anyone noticed (issue #312),
//! because nothing checked them. This is that check.

use std::path::{Path, PathBuf};

use zentinel_config::Config;

/// Repository root, resolved relative to this crate.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root should exist")
}

/// `config/examples`, the canonical example directory.
fn examples_dir() -> PathBuf {
    repo_root().join("config/examples")
}

/// Every directory that ships example configurations.
///
/// `config/examples` is the canonical one. The repository root also had an
/// `examples/` directory, holding two files that had not parsed for some time
/// (issue #353); this sweep only checked `config/examples`, so nothing
/// noticed. Both are checked now, and a root `examples/` is tolerated rather
/// than required, so re-adding one puts it under the same check rather than
/// outside it.
fn example_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![examples_dir()];
    let root_examples = repo_root().join("examples");
    if root_examples.is_dir() {
        dirs.push(root_examples);
    }
    dirs
}

fn example_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = example_dirs()
        .into_iter()
        .flat_map(|dir| {
            std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("{} should be readable: {e}", dir.display()))
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect::<Vec<_>>()
        })
        .filter(|path| path.extension().is_some_and(|ext| ext == "kdl"))
        .collect();
    files.sort();
    files
}

#[test]
fn examples_directory_is_not_empty() {
    // Guards against the sweep below silently passing because it found
    // nothing to check.
    assert!(
        example_files().len() >= 20,
        "expected the shipped examples to still be there, found {}",
        example_files().len()
    );
}

#[test]
fn multi_file_example_loads_and_validates() {
    // Checked through its entry point here, and as a directory below: the
    // files are fragments, so they cannot be checked one by one.
    let entry = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/example-multi-file/zentinel.kdl")
        .canonicalize()
        .expect("multi-file example entry point should exist");

    let config = Config::from_file(&entry)
        .unwrap_or_else(|e| panic!("multi-file example failed to load: {e:#}"));
    config
        .validate()
        .unwrap_or_else(|e| panic!("multi-file example failed to validate: {e}"));

    // The includes must actually contribute: a glob that silently matches
    // nothing would otherwise pass this test with an empty configuration.
    assert!(!config.routes.is_empty(), "includes contributed no routes");
    assert!(
        !config.upstreams.is_empty(),
        "includes contributed no upstreams"
    );
    assert!(
        !config.listeners.is_empty(),
        "includes contributed no listeners"
    );
}

/// #541: the example is also a directory configuration, `zentinel -c
/// config/example-multi-file`. Loaded that way it must read exactly what its
/// entry point reads: each included file once, nothing dropped.
#[test]
fn multi_file_example_loads_as_a_directory() {
    let dir = repo_root().join("config/example-multi-file");

    let from_dir = Config::from_file(&dir)
        .unwrap_or_else(|e| panic!("multi-file example directory failed to load: {e:#}"));
    from_dir
        .validate()
        .unwrap_or_else(|e| panic!("multi-file example directory failed to validate: {e}"));
    let from_entry = Config::from_file(dir.join("zentinel.kdl")).unwrap();

    let ids = |config: &Config| {
        let mut routes: Vec<_> = config.routes.iter().map(|r| r.id.clone()).collect();
        let mut upstreams: Vec<_> = config.upstreams.keys().cloned().collect();
        let mut listeners: Vec<_> = config.listeners.iter().map(|l| l.id.clone()).collect();
        routes.sort();
        upstreams.sort();
        listeners.sort();
        (routes, upstreams, listeners)
    };
    assert_eq!(ids(&from_dir), ids(&from_entry));
    assert!(
        from_dir.listeners.iter().any(|l| l.tls.is_some()),
        "the https listener's TLS settings were dropped"
    );
    assert_eq!(from_dir.limits.max_header_count, 100);
}

/// `test --strict` on the example must have nothing to report, whether given
/// the directory or its entry point, in any of the files.
#[test]
fn multi_file_example_has_no_ignored_settings() {
    let dir = repo_root().join("config/example-multi-file");
    let files = Config::source_files(&dir).expect("example files should be listed");
    assert_eq!(files.len(), 6, "{files:#?}");

    let sources: Vec<_> = files
        .into_iter()
        .map(|f| {
            let text = std::fs::read_to_string(&f).unwrap();
            (f, text)
        })
        .collect();
    let mut result = zentinel_config::validate::ValidationResult::new();
    zentinel_config::validate::unknown_keys::check_unknown_keys_in_files(&sources, &mut result);
    assert!(result.warnings.is_empty(), "{:#?}", result.warnings);
}

#[test]
fn every_shipped_example_loads_and_validates() {
    let mut failures = Vec::new();

    for path in example_files() {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        match Config::from_file(&path) {
            Ok(config) => {
                if let Err(e) = config.validate() {
                    failures.push(format!("{name}: validation failed: {e}"));
                }
            }
            Err(e) => failures.push(format!("{name}: failed to load: {e:#}")),
        }
    }

    assert!(
        failures.is_empty(),
        "shipped example configs must load and validate, but {} failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Builtin handlers that report or change the state of the whole proxy, as
/// opposed to answering a probe.
const ADMIN_HANDLERS: [zentinel_config::BuiltinHandler; 5] = [
    zentinel_config::BuiltinHandler::Config,
    zentinel_config::BuiltinHandler::Upstreams,
    zentinel_config::BuiltinHandler::CacheStats,
    zentinel_config::BuiltinHandler::CachePurge,
    zentinel_config::BuiltinHandler::Metrics,
];

/// The starter configuration, the default configuration files and the
/// container configurations, next to the examples: all of them are meant to
/// be run as they are or copied.
fn shipped_configurations() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = example_files();
    files.push(root.join("config/zentinel.kdl"));
    files.push(root.join("config/example-multi-file/zentinel.kdl"));
    files.push(root.join("deploy/zentinel.starter.kdl"));
    let docker = root.join("config/docker");
    let mut docker_files: Vec<PathBuf> = std::fs::read_dir(&docker)
        .unwrap_or_else(|e| panic!("{} should be readable: {e}", docker.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "kdl"))
        .collect();
    docker_files.sort();
    files.extend(docker_files);
    files
}

/// A route is not tied to a listener unless its namespace has one of its own,
/// so a builtin route written at the top level answers on every top-level
/// listener, whichever one it was meant for. The configuration dump, the
/// upstream status and the cache purge must only be reachable on a loopback
/// listener of a namespace of their own.
#[test]
fn no_shipped_configuration_serves_admin_handlers_off_loopback() {
    let mut offenders = Vec::new();

    for path in shipped_configurations() {
        let name = path
            .strip_prefix(repo_root())
            .unwrap_or(&path)
            .display()
            .to_string();
        let config = Config::from_file(&path)
            .unwrap_or_else(|e| panic!("{name} failed to load: {e:#}"))
            .lower_scopes();

        for listener in &config.listeners {
            let loopback = listener
                .address
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|addr| addr.ip().is_loopback());
            if loopback {
                continue;
            }
            for route in config.routes_served_on(&listener.scope()) {
                if route
                    .builtin_handler
                    .is_some_and(|handler| ADMIN_HANDLERS.contains(&handler))
                {
                    offenders.push(format!(
                        "{name}: route '{}' ({:?}) is served on listener '{}' at {}",
                        route.id, route.builtin_handler, listener.id, listener.address
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "admin handlers are served off loopback:\n  {}",
        offenders.join("\n  ")
    );
}

/// The metrics server binds loopback unless told otherwise, and the container
/// configurations are scraped from another container. A metrics address that
/// is not loopback can only have been written in the file, since the default
/// is loopback.
#[test]
fn container_configurations_name_a_metrics_address_other_than_loopback() {
    let docker = repo_root().join("config/docker");
    let mut checked = 0;
    for entry in std::fs::read_dir(&docker).expect("config/docker is readable") {
        let path = entry.expect("entry is readable").path();
        if path.extension().is_none_or(|ext| ext != "kdl") {
            continue;
        }
        let config = Config::from_file(&path)
            .unwrap_or_else(|e| panic!("{} failed to load: {e:#}", path.display()));
        if config.observability.metrics.enabled {
            let address = &config.observability.metrics.address;
            let loopback = address
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|addr| addr.ip().is_loopback());
            assert!(
                !loopback,
                "{} scrapes the metrics server from outside the container, but its \
                 address is {address}",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 2,
        "expected the container configurations, found {checked}"
    );
}

/// The chart's values file.
fn helm_values() -> String {
    std::fs::read_to_string(repo_root().join("deploy/helm/zentinel/values.yaml"))
        .expect("the chart's values are readable")
}

/// The block scalar `key: |` of `values`, dedented.
///
/// The config crate has no YAML parser, and the chart's values only need a
/// literal block read back, so this reads it as text: the lines after the
/// first `key: |` that are blank or indented deeper than the key.
fn yaml_block(values: &str, key: &str) -> String {
    let header = format!("{key}: |");
    let mut lines = values.lines();
    let indent = lines
        .by_ref()
        .find_map(|line| (line.trim() == header).then(|| line.len() - line.trim_start().len()))
        .unwrap_or_else(|| panic!("no `{header}` block in the chart's values"));
    let body: Vec<&str> = lines
        .take_while(|line| line.trim().is_empty() || line.len() - line.trim_start().len() > indent)
        .collect();
    let strip = body
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    body.iter()
        .map(|line| line.get(strip..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The integer value of the first `key: <n>` line of `values`.
fn yaml_port(values: &str, key: &str) -> u16 {
    let prefix = format!("{key}:");
    values
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no `{key}` in the chart's values"))
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("`{key}` in the chart's values is not a port: {e}"))
}

/// The chart's `proxy.config.kdl`, parsed as the proxy parses it.
fn helm_chart_config() -> Config {
    Config::from_kdl(&yaml_block(&helm_values(), "kdl"))
        .unwrap_or_else(|e| panic!("the chart's proxy.config.kdl does not parse: {e:#}"))
}

/// The chart ships a configuration in `proxy.config.kdl`, and nothing parsed
/// it: it was written in a syntax the parser has not accepted for a long
/// time (top-level `listener`, `upstream` and `route`, `matches { all true
/// }`), so every install with the default values failed to start.
#[test]
fn helm_chart_configuration_loads_and_validates() {
    let kdl = yaml_block(&helm_values(), "kdl");
    let config = helm_chart_config();
    config
        .validate()
        .unwrap_or_else(|e| panic!("the chart's proxy.config.kdl does not validate: {e}"));

    // `zentinel test --strict`: nothing in it is silently ignored.
    let mut result = zentinel_config::validate::ValidationResult::new();
    zentinel_config::validate::unknown_keys::check_unknown_keys_in_files(
        &[(PathBuf::from("values.yaml#proxy.config.kdl"), kdl)],
        &mut result,
    );
    assert!(result.warnings.is_empty(), "{:#?}", result.warnings);

    assert!(
        !config.routes.is_empty(),
        "the chart's config has no routes"
    );
    assert!(
        !config.upstreams.is_empty(),
        "the chart's config has no upstreams"
    );
}

/// The chart is scraped through the pod IP, so its metrics server is not on
/// loopback, and it is on the port the pod and the Service expose as
/// `metrics`.
#[test]
fn helm_chart_metrics_server_is_on_the_metrics_port() {
    let config = helm_chart_config();
    let metrics = &config.observability.metrics;
    assert!(metrics.enabled, "the chart's metrics server is disabled");
    let address: std::net::SocketAddr = metrics
        .address
        .parse()
        .expect("the chart's metrics address is a socket address");
    assert!(
        !address.ip().is_loopback(),
        "the chart's metrics server is on loopback: {address}"
    );
    assert_eq!(
        address.port(),
        yaml_port(&helm_values(), "metricsPort"),
        "the chart's metrics address and proxy.service.metricsPort disagree"
    );
}

/// The pod's liveness and readiness probes ask for /health and /ready on the
/// container port `health`, proxy.service.healthPort. The metrics server
/// answers 404 to both, so they must be served by a listener of the chart's
/// configuration on that port, reachable from the kubelet (not loopback),
/// with the health builtin.
#[test]
fn helm_chart_probes_reach_the_health_handler() {
    let values = helm_values();
    let health_port = yaml_port(&values, "healthPort");
    assert_ne!(
        health_port,
        yaml_port(&values, "metricsPort"),
        "the health listener and the metrics server cannot share a port"
    );

    // Both probes name the `health` port, and the deployment defines it.
    for probe in ["livenessProbe", "readinessProbe"] {
        let block = yaml_block_lines(&values, probe);
        assert!(
            block.iter().any(|line| line.trim() == "port: health"),
            "{probe} does not use the `health` port: {block:#?}"
        );
    }
    let deployment = std::fs::read_to_string(
        repo_root().join("deploy/helm/zentinel/templates/proxy-deployment.yaml"),
    )
    .expect("the chart's deployment template is readable");
    assert!(
        deployment.contains(
            "- name: health\n          containerPort: {{ .Values.proxy.service.healthPort }}"
        ),
        "the deployment does not define container port `health` from proxy.service.healthPort"
    );

    let config = helm_chart_config().lower_scopes();
    let listener = config
        .listeners
        .iter()
        .find(|listener| {
            listener
                .address
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|addr| addr.port() == health_port)
        })
        .unwrap_or_else(|| panic!("no listener of the chart's config is on port {health_port}"));
    let address: std::net::SocketAddr = listener.address.parse().unwrap();
    assert!(
        !address.ip().is_loopback(),
        "the kubelet probes the pod IP, but the health listener is on {address}"
    );

    let routes = config.routes_served_on(&listener.scope());
    let health = routes
        .iter()
        .find(|route| route.builtin_handler == Some(zentinel_config::BuiltinHandler::Health))
        .unwrap_or_else(|| {
            panic!(
                "listener '{}' does not serve the health handler",
                listener.id
            )
        });
    // The same condition as the starter's admin listener, whose matching is
    // checked against the proxy's route matcher in zentinel-proxy's
    // `default_configuration_routes` tests.
    assert!(
        health.matches.iter().any(|m| matches!(
            m,
            zentinel_config::MatchCondition::PathRegex(re) if re == "^/(health|healthz|ready)$"
        )),
        "the health route does not match /health and /ready: {:?}",
        health.matches
    );
    // Not an admin surface: the probe listener is reachable from the cluster.
    for route in &routes {
        assert!(
            route.builtin_handler == Some(zentinel_config::BuiltinHandler::Health),
            "route '{}' is served on the probe listener",
            route.id
        );
    }
}

/// The lines of the YAML mapping under the first `key:` line.
fn yaml_block_lines<'a>(values: &'a str, key: &str) -> Vec<&'a str> {
    let header = format!("{key}:");
    let mut lines = values.lines();
    let indent = lines
        .by_ref()
        .find_map(|line| (line.trim() == header).then(|| line.len() - line.trim_start().len()))
        .unwrap_or_else(|| panic!("no `{header}` in the chart's values"));
    lines
        .take_while(|line| line.trim().is_empty() || line.len() - line.trim_start().len() > indent)
        .collect()
}

/// The configurations the container images and compose stacks run and the
/// starter, loaded and validated like the examples. (The chart's is checked
/// above.)
///
/// Validation also checks that the directory of each agent's Unix socket
/// exists, which holds inside the container the configuration is written for
/// (`/var/run/zentinel` in config/docker/proxy.kdl) but not on the machine
/// running the tests, so that one error is not counted here.
#[test]
fn deployment_configurations_load_and_validate() {
    let root = repo_root();
    let mut failures = Vec::new();
    for path in shipped_configurations() {
        let name = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        match Config::from_file(&path) {
            Ok(config) => {
                if let Err(e) = config.validate() {
                    let message = e.to_string();
                    if !message.contains("unix socket path parent directory doesn't exist") {
                        failures.push(format!("{name}: validation failed: {message}"));
                    }
                }
            }
            Err(e) => failures.push(format!("{name}: failed to load: {e:#}")),
        }
    }
    assert!(
        failures.is_empty(),
        "deployment configurations must load and validate, but {} failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// The compose stacks mount config/docker/proxy.kdl, whose /health is on the
/// HTTP listener; :9090 is the metrics server and answers 404 to /health.
/// The proxy image is distroless, so a `curl` healthcheck cannot run at all.
#[test]
fn compose_files_do_not_probe_health_on_the_metrics_port() {
    for file in ["docker-compose.yml", "docker-compose.test.yml"] {
        let text = std::fs::read_to_string(repo_root().join(file))
            .unwrap_or_else(|e| panic!("{file} should be readable: {e}"));
        assert!(
            !text.contains(":9090/health") && !text.contains(":9090/ready"),
            "{file} asks the metrics port for a health path"
        );
    }
}
