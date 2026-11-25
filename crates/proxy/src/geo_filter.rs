//! GeoIP filtering for Zentinel proxy
//!
//! This module provides geolocation-based request filtering using MaxMind GeoLite2/GeoIP2
//! and IP2Location databases. Filters can block, allow, or log requests based on country.
//!
//! # Features
//! - Support for MaxMind (.mmdb) and IP2Location (.bin) databases
//! - Block mode (blocklist) and Allow mode (allowlist)
//! - Log-only mode for monitoring without blocking
//! - Per-filter IP→Country caching with configurable TTL
//! - Configurable fail-open/fail-closed on lookup errors
//! - X-GeoIP-Country response header injection

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use dashmap::DashMap;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, trace, warn};

use zentinel_config::{
    Config, Filter, GeoDatabaseType, GeoFailureMode, GeoFilter, GeoFilterAction,
};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during geo lookup
#[derive(Debug, Clone)]
pub enum GeoLookupError {
    /// IP address could not be parsed
    InvalidIp(String),
    /// Database error during lookup
    DatabaseError(String),
    /// Database file could not be loaded
    LoadError(String),
}

impl std::fmt::Display for GeoLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeoLookupError::InvalidIp(ip) => write!(f, "invalid IP address: {}", ip),
            GeoLookupError::DatabaseError(msg) => write!(f, "database error: {}", msg),
            GeoLookupError::LoadError(msg) => write!(f, "failed to load database: {}", msg),
        }
    }
}

impl std::error::Error for GeoLookupError {}

// =============================================================================
// GeoDatabase Trait
// =============================================================================

/// Trait for GeoIP database backends
pub trait GeoDatabase: Send + Sync {
    /// Look up the country code for an IP address
    fn lookup(&self, ip: IpAddr) -> Result<Option<String>, GeoLookupError>;

    /// Get the database type
    fn database_type(&self) -> GeoDatabaseType;
}

// =============================================================================
// Trial lookups
// =============================================================================

/// The IPv4 addresses looked up in a database as soon as it is open: both
/// ends of the address space, which the `ip2location` crate's own tests
/// look up too, and an address of the documentation range between them.
const TRIAL_IPV4: [Ipv4Addr; 3] = [
    Ipv4Addr::new(0, 0, 0, 0),
    Ipv4Addr::new(192, 0, 2, 1),
    Ipv4Addr::new(255, 255, 255, 255),
];

/// The IPv6 addresses looked up in a database that has IPv6 data as soon as
/// it is open: two of the documentation ranges, which are in different
/// parts of the address space.
const TRIAL_IPV6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
    Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 1),
];

/// The error for a database whose trial lookup of `ip` failed.
fn trial_failure(
    backend: &str,
    path: &Path,
    ip: IpAddr,
    error: impl std::fmt::Display,
) -> GeoLookupError {
    GeoLookupError::LoadError(format!(
        "failed to open {backend} database {path:?}: the trial lookup of {ip} failed: {error}"
    ))
}

// =============================================================================
// MaxMind Database Backend
// =============================================================================

/// MaxMind GeoLite2/GeoIP2 database backend
pub struct MaxMindDatabase {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl MaxMindDatabase {
    /// Open a MaxMind database file
    ///
    /// Looks up the trial addresses before it returns: an address with no
    /// record is fine, any other failure is an error.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GeoLookupError> {
        let path = path.as_ref();
        let reader = maxminddb::Reader::open_readfile(path).map_err(|e| {
            GeoLookupError::LoadError(format!("failed to open MaxMind database {:?}: {}", path, e))
        })?;
        let database = Self { reader };
        database.trial_lookups(path)?;

        debug!(path = ?path, "Opened MaxMind GeoIP database");
        Ok(database)
    }

    /// Look up the trial addresses. A database of IP version 4 is not asked
    /// about IPv6 addresses, which `maxminddb` refuses in one.
    fn trial_lookups(&self, path: &Path) -> Result<(), GeoLookupError> {
        let ipv6 = self.reader.metadata().ip_version != 4;
        let ipv4 = TRIAL_IPV4.into_iter().map(IpAddr::V4);
        let ipv6 = TRIAL_IPV6.into_iter().map(IpAddr::V6).filter(|_| ipv6);
        for ip in ipv4.chain(ipv6) {
            self.lookup(ip)
                .map_err(|e| trial_failure("MaxMind", path, ip, e))?;
        }
        Ok(())
    }
}

impl GeoDatabase for MaxMindDatabase {
    fn lookup(&self, ip: IpAddr) -> Result<Option<String>, GeoLookupError> {
        match self.reader.lookup(ip) {
            Ok(result) => {
                if !result.has_data() {
                    trace!(ip = %ip, "IP not found in MaxMind database");
                    return Ok(None);
                }
                match result.decode::<maxminddb::geoip2::Country>() {
                    Ok(Some(record)) => {
                        let country_code = record.country.iso_code.map(|s| s.to_string());
                        trace!(ip = %ip, country = ?country_code, "MaxMind lookup");
                        Ok(country_code)
                    }
                    Ok(None) => {
                        trace!(ip = %ip, "No country data for IP in MaxMind database");
                        Ok(None)
                    }
                    Err(e) => {
                        warn!(ip = %ip, error = %e, "MaxMind decode error");
                        Err(GeoLookupError::DatabaseError(e.to_string()))
                    }
                }
            }
            Err(e) => {
                warn!(ip = %ip, error = %e, "MaxMind lookup error");
                Err(GeoLookupError::DatabaseError(e.to_string()))
            }
        }
    }

    fn database_type(&self) -> GeoDatabaseType {
        GeoDatabaseType::MaxMind
    }
}

// =============================================================================
// IP2Location Database Backend
// =============================================================================

/// IP2Location database backend
pub struct Ip2LocationDatabase {
    db: ip2location::DB,
}

impl Ip2LocationDatabase {
    /// Open an IP2Location database file
    ///
    /// The `ip2location` crate maps the file and reads only its header when it
    /// opens it, so a file that was cut short opens, and the lookups that read
    /// the part that is missing fail, each applying the filter's `on-failure`
    /// to its request. Two checks are made here instead:
    ///
    /// - A file shorter than the size its header records is refused. Files of
    ///   product code 0, some older ones, and files that record no size are
    ///   not checked.
    /// - The trial addresses are looked up, and a failure other than "no
    ///   record" is an error. That finds other damage in what the lookups
    ///   read. The addresses are a sample, spread over the address space, and
    ///   do not show that the whole file can be read.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GeoLookupError> {
        let path = path.as_ref();
        let db = ip2location::DB::from_file(path).map_err(|e| {
            GeoLookupError::LoadError(format!(
                "failed to open IP2Location database {:?}: {}",
                path, e
            ))
        })?;

        // The header is read again here, by the path, and not from the map. A
        // file being replaced can be read as the header of the one and the
        // map of the other; then the next change event, or the periodic
        // check, reads the database again.
        let header = Ip2LocationHeader::read(path);
        if let Ok(header) = &header {
            if header.is_cut_short() {
                return Err(GeoLookupError::LoadError(format!(
                    "failed to open IP2Location database {:?}: the file is cut short: \
                     it is {} bytes and its header records {} bytes",
                    path, header.file_size, header.recorded_size
                )));
            }
        }
        // A header that cannot be read counts as having IPv6 rows, so that
        // the IPv6 addresses are looked up and a failure stands.
        let with_ipv6 = match &header {
            Ok(header) => header.ipv6_rows != 0,
            Err(_) => true,
        };

        let database = Self { db };
        database.trial_lookups(path, with_ipv6)?;

        debug!(path = ?path, "Opened IP2Location GeoIP database");
        Ok(database)
    }

    /// Look up the trial addresses. The IPv6 ones only when the file has IPv6
    /// rows: what the crate answers for an IPv6 address in a file without
    /// them depends on where its header says they would start.
    fn trial_lookups(&self, path: &Path, with_ipv6: bool) -> Result<(), GeoLookupError> {
        if !with_ipv6 {
            debug!(path = ?path, "IP2Location database has no IPv6 rows");
        }
        let ipv4 = TRIAL_IPV4.into_iter().map(IpAddr::V4);
        let ipv6 = TRIAL_IPV6.into_iter().map(IpAddr::V6).filter(|_| with_ipv6);
        for ip in ipv4.chain(ipv6) {
            match self.db.ip_lookup(ip) {
                Ok(_) | Err(ip2location::error::Error::RecordNotFound) => {}
                Err(e) => return Err(trial_failure("IP2Location", path, ip, e)),
            }
        }
        Ok(())
    }
}

/// The fields of the header of an IP2Location file that are used here, and
/// the size of the file. The `ip2location` crate reads the header too, but
/// does not give these.
struct Ip2LocationHeader {
    /// The count of IPv6 rows
    ipv6_rows: u32,
    /// 1 for the files of IP2Location, 0 for some older ones
    product_code: u8,
    /// The size of the whole file, as the file records it; 0 for none
    recorded_size: u32,
    /// The size of the file
    file_size: u64,
}

impl Ip2LocationHeader {
    /// The length of the part of the header that is read.
    const LEN: usize = 35;

    /// Read the header of the file at `path`, and its size, from one open of
    /// the file. The offsets are those of `read_header` in the crate (which
    /// counts from 1): the count of IPv6 rows is the four bytes at 13, the
    /// product code the byte at 29, and the size the four bytes at 31, in
    /// little endian.
    fn read(path: &Path) -> std::io::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut header = [0u8; Self::LEN];
        file.read_exact(&mut header)?;
        let u32_at = |at: usize| {
            u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
        };
        Ok(Self {
            ipv6_rows: u32_at(13),
            product_code: header[29],
            recorded_size: u32_at(31),
            file_size: file.metadata()?.len(),
        })
    }

    /// Whether the file is shorter than its header records. Files of product
    /// code 0, some older ones, and files that record no size are not
    /// checked.
    fn is_cut_short(&self) -> bool {
        self.product_code == 1
            && self.recorded_size != 0
            && self.file_size < u64::from(self.recorded_size)
    }
}

impl GeoDatabase for Ip2LocationDatabase {
    fn lookup(&self, ip: IpAddr) -> Result<Option<String>, GeoLookupError> {
        match self.db.ip_lookup(ip) {
            Ok(record) => {
                // Record is an enum - extract country from the LocationDb variant
                let country_code = match record {
                    ip2location::Record::LocationDb(loc) => {
                        loc.country.map(|c| c.short_name.to_string())
                    }
                    ip2location::Record::ProxyDb(proxy) => {
                        proxy.country.map(|c| c.short_name.to_string())
                    }
                };
                trace!(ip = %ip, country = ?country_code, "IP2Location lookup");
                Ok(country_code)
            }
            Err(ip2location::error::Error::RecordNotFound) => {
                trace!(ip = %ip, "IP not found in IP2Location database");
                Ok(None)
            }
            Err(e) => {
                warn!(ip = %ip, error = %e, "IP2Location lookup error");
                Err(GeoLookupError::DatabaseError(e.to_string()))
            }
        }
    }

    fn database_type(&self) -> GeoDatabaseType {
        GeoDatabaseType::Ip2Location
    }
}

// =============================================================================
// Cached Country Entry
// =============================================================================

/// Cached country lookup result
struct CachedCountry {
    /// The country code (or None if not found)
    country_code: Option<String>,
    /// When this entry was cached
    cached_at: Instant,
}

// =============================================================================
// GeoFilterResult
// =============================================================================

/// Result of a geo filter check
#[derive(Debug, Clone)]
pub struct GeoFilterResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// The country code (if found)
    pub country_code: Option<String>,
    /// Whether this was a cache hit
    pub cache_hit: bool,
    /// Whether to add the country header
    pub add_header: bool,
    /// HTTP status code to return if blocked
    pub status_code: u16,
    /// Block message to return if blocked
    pub block_message: Option<String>,
}

// =============================================================================
// Database files
// =============================================================================

/// What a database file looked like at one moment, to tell that it changed:
/// its size and modification time and, where there are such things, the
/// device and inode it is on. A file written next to it and renamed over it
/// differs in the inode, whatever its size and time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl FileStamp {
    /// The stamp of the file at `path`, following links; none when the file
    /// cannot be looked at.
    fn of(path: &Path) -> Option<Self> {
        let metadata = std::fs::metadata(path).ok()?;
        Some(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        })
    }
}

/// What a [`GeoFilterPool`] knows of the file its database is read from.
struct DatabaseFile {
    /// The file as it was when its database was last opened, or opened again
    /// without success. A file that stays as it is does not need opening
    /// again, whether or not the last time worked.
    tried: Option<FileStamp>,
    /// The file as it was at the previous periodic check.
    seen: Option<FileStamp>,
}

// =============================================================================
// GeoFilterPool
// =============================================================================

/// Most lookup results one geo filter keeps cached. An entry is an address,
/// a country code and a timestamp (well under 100 bytes), so a full cache is
/// a few megabytes.
pub(crate) const GEO_CACHE_MAX_ENTRIES: usize = 100_000;

/// A single geo filter instance with its database and cache
pub struct GeoFilterPool {
    /// The underlying GeoIP database (wrapped in RwLock for hot reload)
    database: RwLock<Arc<dyn GeoDatabase>>,
    /// IP → Country cache
    cache: DashMap<IpAddr, CachedCountry>,
    /// Filter configuration
    config: GeoFilter,
    /// Pre-computed set of countries for fast lookup
    countries_set: HashSet<String>,
    /// Cache TTL duration
    cache_ttl: Duration,
    /// Database file path for reload
    database_path: PathBuf,
    /// Database type
    database_type: GeoDatabaseType,
    /// The database file as the pool last saw it
    file: Mutex<DatabaseFile>,
}

impl GeoFilterPool {
    /// Create a new geo filter pool from configuration
    pub fn new(config: GeoFilter) -> Result<Self, GeoLookupError> {
        // The configured type, else the one the extension says. A path that
        // says nothing is refused when the configuration loads; a filter that
        // got here without that check is refused instead of guessed at.
        let db_type = config.resolved_database_type().ok_or_else(|| {
            GeoLookupError::LoadError(format!(
                "cannot tell the database type of {:?} from its extension; \
                 set database-type",
                config.database_path
            ))
        })?;

        let database_path = PathBuf::from(&config.database_path);

        // The file is looked at before it is opened: one replaced in between
        // then counts as changed since, and is read once more, rather than
        // not at all.
        let stamp = FileStamp::of(&database_path);

        // Open the database
        let database: Arc<dyn GeoDatabase> = match db_type {
            GeoDatabaseType::MaxMind => Arc::new(MaxMindDatabase::open(&config.database_path)?),
            GeoDatabaseType::Ip2Location => {
                Arc::new(Ip2LocationDatabase::open(&config.database_path)?)
            }
        };

        // Build countries set for fast lookup
        let countries_set: HashSet<String> = config.countries.iter().cloned().collect();

        let cache_ttl = Duration::from_secs(config.cache_ttl_secs);

        debug!(
            database_path = %config.database_path,
            database_type = ?db_type,
            action = ?config.action,
            countries_count = countries_set.len(),
            cache_ttl_secs = config.cache_ttl_secs,
            "Created GeoFilterPool"
        );

        Ok(Self {
            database: RwLock::new(database),
            cache: DashMap::new(),
            config,
            countries_set,
            cache_ttl,
            database_path,
            database_type: db_type,
            file: Mutex::new(DatabaseFile {
                tried: stamp,
                seen: stamp,
            }),
        })
    }

    /// Reload the database from disk
    ///
    /// This atomically swaps the database and clears the cache.
    ///
    /// # Errors
    ///
    /// Fails when the new database does not open (see
    /// [`MaxMindDatabase::open`] and [`Ip2LocationDatabase::open`], which
    /// look up trial addresses before they succeed). The database in use,
    /// and its cache, are then left as they are. The file is not tried again
    /// by [`Self::reload_if_file_changed`] until it changes.
    pub fn reload_database(&self) -> Result<(), GeoLookupError> {
        info!(
            database_path = %self.database_path.display(),
            database_type = ?self.database_type,
            "Reloading geo database"
        );

        // As in `new`, the file is looked at before it is opened. It is
        // noted whether or not it opens, so that a file that does not open is
        // not tried again each time the periodic check comes round.
        let stamp = FileStamp::of(&self.database_path);
        *self.file.lock() = DatabaseFile {
            tried: stamp,
            seen: stamp,
        };

        // Open the new database
        let new_database: Arc<dyn GeoDatabase> = match self.database_type {
            GeoDatabaseType::MaxMind => Arc::new(MaxMindDatabase::open(&self.database_path)?),
            GeoDatabaseType::Ip2Location => {
                Arc::new(Ip2LocationDatabase::open(&self.database_path)?)
            }
        };

        // Atomically swap the database
        {
            let mut db = self.database.write();
            *db = new_database;
        }

        // Clear the cache since country mappings may have changed
        self.cache.clear();

        info!(
            database_path = %self.database_path.display(),
            "Geo database reloaded successfully"
        );

        Ok(())
    }

    /// The periodic check of the database file.
    ///
    /// Reloads the database (see [`Self::reload_database`]) when the file
    /// differs from the one the database in use was opened from, in its size,
    /// modification time or, on Unix, device and inode, and has not changed
    /// since the previous call: a file still being written is left until it
    /// has stayed as it is for a whole interval between two calls. Returns
    /// the result of the reload, or none when there was none.
    ///
    /// A file that was read again for a change event is not read again here,
    /// and neither is one whose reload failed, until it changes. A file that
    /// cannot be looked at is left alone.
    pub fn reload_if_file_changed(&self) -> Option<Result<(), GeoLookupError>> {
        let now = FileStamp::of(&self.database_path);
        let due = {
            let mut file = self.file.lock();
            let due = now.is_some() && now != file.tried && now == file.seen;
            file.seen = now;
            due
        };
        if !due {
            return None;
        }
        info!(
            database_path = %self.database_path.display(),
            "Geo database file has changed since it was opened"
        );
        Some(self.reload_database())
    }

    /// Get the database file path
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    /// Check if a client IP should be allowed or blocked
    pub fn check(&self, client_ip: &str) -> GeoFilterResult {
        // Parse the IP address
        let ip: IpAddr = match client_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(client_ip = %client_ip, "Failed to parse client IP for geo filter");
                return self.handle_failure();
            }
        };

        // Check cache first
        let now = Instant::now();
        if let Some(entry) = self.cache.get(&ip) {
            if now.duration_since(entry.cached_at) < self.cache_ttl {
                trace!(ip = %ip, country = ?entry.country_code, "Geo cache hit");
                return self.evaluate(entry.country_code.clone(), true);
            }
            // Entry expired, will be replaced
        }

        // Lookup in database
        let database = self.database.read();
        match database.lookup(ip) {
            Ok(country_code) => {
                self.cache_result(ip, country_code.clone(), now);
                self.evaluate(country_code, false)
            }
            Err(e) => {
                warn!(ip = %ip, error = %e, "Geo lookup failed");
                self.handle_failure()
            }
        }
    }

    /// Cache a lookup result, keeping the cache at most
    /// [`GEO_CACHE_MAX_ENTRIES`] entries.
    ///
    /// The cache is keyed by the full client address, so a client that
    /// changes address often (any IPv6 client can within its prefix) adds an
    /// entry per request. When the cache is full, expired entries are removed;
    /// if it is still full, the result is not cached. The lookup itself is
    /// unaffected, so a full cache costs a database lookup per request, never
    /// a wrong answer.
    fn cache_result(&self, ip: IpAddr, country_code: Option<String>, now: Instant) {
        if self.cache.len() >= GEO_CACHE_MAX_ENTRIES && !self.cache.contains_key(&ip) {
            self.clear_expired();
            if self.cache.len() >= GEO_CACHE_MAX_ENTRIES {
                trace!(ip = %ip, "Geo cache full; result not cached");
                return;
            }
        }
        self.cache.insert(
            ip,
            CachedCountry {
                country_code,
                cached_at: now,
            },
        );
    }

    /// Evaluate the filter action based on country code
    fn evaluate(&self, country_code: Option<String>, cache_hit: bool) -> GeoFilterResult {
        let in_list = country_code
            .as_ref()
            .map(|c| self.countries_set.contains(c))
            .unwrap_or(false);

        let allowed = match self.config.action {
            GeoFilterAction::Block => {
                // Block mode: block if country is in the list
                !in_list
            }
            GeoFilterAction::Allow => {
                // Allow mode: allow only if country is in the list. An empty
                // list allows nobody. A KDL configuration refuses one, and so
                // does `Config::validate` for top-level filters; a JSON or
                // TOML filter inside a namespace or service is not checked
                // and can still reach this.
                in_list
            }
            GeoFilterAction::LogOnly => {
                // Log-only mode: always allow
                true
            }
        };

        trace!(
            country = ?country_code,
            in_list = in_list,
            action = ?self.config.action,
            allowed = allowed,
            "Geo filter evaluation"
        );

        GeoFilterResult {
            allowed,
            country_code,
            cache_hit,
            add_header: self.config.add_country_header,
            status_code: self.config.status_code,
            block_message: self.config.block_message.clone(),
        }
    }

    /// Handle lookup failure based on failure mode
    fn handle_failure(&self) -> GeoFilterResult {
        let allowed = match self.config.on_failure {
            GeoFailureMode::Open => true,
            GeoFailureMode::Closed => false,
        };

        GeoFilterResult {
            allowed,
            country_code: None,
            cache_hit: false,
            add_header: false,
            status_code: self.config.status_code,
            block_message: self.config.block_message.clone(),
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let now = Instant::now();
        let total = self.cache.len();
        let valid = self
            .cache
            .iter()
            .filter(|e| now.duration_since(e.cached_at) < self.cache_ttl)
            .count();
        (total, valid)
    }

    /// Clear expired cache entries
    pub fn clear_expired(&self) {
        let now = Instant::now();
        self.cache
            .retain(|_, v| now.duration_since(v.cached_at) < self.cache_ttl);
    }

    /// Create a GeoFilterPool with a pre-built database (for testing).
    #[cfg(test)]
    pub(crate) fn new_with_database(config: GeoFilter, database: Arc<dyn GeoDatabase>) -> Self {
        let countries_set: HashSet<String> = config.countries.iter().cloned().collect();
        let cache_ttl = Duration::from_secs(config.cache_ttl_secs);
        let database_path = PathBuf::from(&config.database_path);
        let database_type = config
            .database_type
            .clone()
            .unwrap_or(GeoDatabaseType::MaxMind);

        Self {
            database: RwLock::new(database),
            cache: DashMap::new(),
            config,
            countries_set,
            cache_ttl,
            database_path,
            database_type,
            file: Mutex::new(DatabaseFile {
                tried: None,
                seen: None,
            }),
        }
    }
}

// =============================================================================
// GeoFilterManager
// =============================================================================

/// What [`GeoFilterManager::apply`] did, counted per filter.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GeoFilterChanges {
    /// Filters that were not registered and now are.
    pub added: usize,
    /// Filters whose settings changed, now served by a new pool (and an
    /// empty cache).
    pub replaced: usize,
    /// Filters whose settings did not change; their pool and cache are kept.
    pub unchanged: usize,
}

/// The pools of every geo filter of a configuration, built and not yet in use.
///
/// Made by [`GeoFilterManager::prepare`], which opens every database that
/// needs it, and put in use by [`GeoFilterManager::apply`] and
/// [`GeoFilterManager::remove_unlisted`], which cannot fail. Dropping a plan
/// changes nothing.
#[must_use = "a plan does nothing until it is applied"]
pub struct GeoFilterPlan {
    pools: HashMap<String, Arc<GeoFilterPool>>,
}

/// The geo filters of `config`, in the order of their ids.
fn geo_filters(config: &Config) -> Vec<(&String, &GeoFilter)> {
    let mut geo_filters: Vec<(&String, &GeoFilter)> = config
        .filters
        .iter()
        .filter_map(|(id, filter)| match &filter.filter {
            Filter::Geo(geo) => Some((id, geo)),
            _ => None,
        })
        .collect();
    geo_filters.sort_by_key(|(id, _)| *id);
    geo_filters
}

/// A line of the error that lists the filters whose database did not open.
fn load_failure(filter_id: &str, geo_filter: &GeoFilter, error: &GeoLookupError) -> String {
    format!(
        "  - filter '{}', database-path '{}': {}",
        filter_id, geo_filter.database_path, error
    )
}

/// The error for the filters whose database did not open.
fn load_failures(failures: &[String]) -> anyhow::Error {
    anyhow::anyhow!(
        "{} geo filter(s) cannot be used, because their databases did not load:\n{}",
        failures.len(),
        failures.join("\n")
    )
}

/// Manages all geo filter instances
pub struct GeoFilterManager {
    /// Filter ID → GeoFilterPool mapping
    filter_pools: DashMap<String, Arc<GeoFilterPool>>,
}

impl GeoFilterManager {
    /// Create a new empty geo filter manager
    pub fn new() -> Self {
        Self {
            filter_pools: DashMap::new(),
        }
    }

    /// Register every geo filter of `config`, opening its database.
    ///
    /// `config` is the lowered configuration (see `Config::lower_scopes`), so
    /// the geo filters of namespaces and services are among its filters.
    ///
    /// # Errors
    ///
    /// Fails when the database of any geo filter does not open. The error
    /// lists every filter that failed, in the order of their ids, with its
    /// `database-path` and the reason.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let manager = Self::new();
        let plan = manager.prepare(config)?;
        manager.apply(&plan);

        let filter_ids = manager.filter_ids();
        if !filter_ids.is_empty() {
            info!(
                filter_count = filter_ids.len(),
                filter_ids = ?filter_ids,
                "GeoIP filtering initialized"
            );
        }

        Ok(manager)
    }

    /// Open the database of every geo filter of `config`, without keeping
    /// any of them open, for a configuration that is only being checked.
    ///
    /// Opens each database the way [`Self::from_config`] does, one after the
    /// other, so no more than one is held in memory at a time.
    ///
    /// # Errors
    ///
    /// Fails when the database of any geo filter does not open. The error is
    /// the one [`Self::from_config`] gives.
    pub fn check_databases(config: &Config) -> anyhow::Result<()> {
        let mut failures = Vec::new();
        for (filter_id, geo_filter) in geo_filters(config) {
            if let Err(e) = GeoFilterPool::new(geo_filter.clone()) {
                failures.push(load_failure(filter_id, geo_filter, &e));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(load_failures(&failures))
        }
    }

    /// Build the pools of the geo filters of `config`, to bring this manager
    /// up to date with it, without changing the manager.
    ///
    /// A filter whose settings (`database-path` included) are what this
    /// manager's pool for the id was built from keeps that pool, and with it
    /// its database and cache. Every other filter of `config` gets a new pool,
    /// whose database is opened here. [`Self::apply`] then puts the plan in
    /// use.
    ///
    /// Opens databases, which blocks on file reads.
    ///
    /// # Errors
    ///
    /// Fails when the database of any geo filter that needs a new pool does
    /// not open. The error lists every filter that failed, in the order of
    /// their ids, with its `database-path` and the reason. Nothing has been
    /// changed.
    pub fn prepare(&self, config: &Config) -> anyhow::Result<GeoFilterPlan> {
        self.prepare_with(config, GeoFilterPool::new)
    }

    /// [`Self::prepare`], with the function that builds a new pool.
    fn prepare_with(
        &self,
        config: &Config,
        open: impl Fn(GeoFilter) -> Result<GeoFilterPool, GeoLookupError>,
    ) -> anyhow::Result<GeoFilterPlan> {
        let mut pools = HashMap::new();
        let mut failures = Vec::new();
        for (filter_id, geo_filter) in geo_filters(config) {
            let current = self
                .filter_pools
                .get(filter_id)
                .map(|pool| Arc::clone(pool.value()));
            match current {
                Some(pool) if pool.config == *geo_filter => {
                    pools.insert(filter_id.clone(), pool);
                }
                _ => match open(geo_filter.clone()) {
                    Ok(pool) => {
                        pools.insert(filter_id.clone(), Arc::new(pool));
                    }
                    Err(e) => failures.push(load_failure(filter_id, geo_filter, &e)),
                },
            }
        }
        if failures.is_empty() {
            Ok(GeoFilterPlan { pools })
        } else {
            Err(load_failures(&failures))
        }
    }

    /// Put a plan from [`Self::prepare`] in use: register the filters it
    /// adds and replace the ones whose pool it rebuilt.
    ///
    /// Filters the plan does not name stay registered, for the routes that
    /// still name them; [`Self::remove_unlisted`] drops them once those routes
    /// are gone. The plan was made from this manager as it is now, so apply it
    /// before anything else changes the manager.
    ///
    /// A filter is replaced in one step, but the filters of a plan are not
    /// all replaced at one instant: for a moment, a request may meet one
    /// filter as it was and another as it is to be.
    pub fn apply(&self, plan: &GeoFilterPlan) -> GeoFilterChanges {
        let mut changes = GeoFilterChanges::default();
        for (filter_id, pool) in &plan.pools {
            let registered = match self
                .filter_pools
                .insert(filter_id.clone(), Arc::clone(pool))
            {
                None => {
                    changes.added += 1;
                    "Registered geo filter"
                }
                Some(old) if Arc::ptr_eq(&old, pool) => {
                    changes.unchanged += 1;
                    continue;
                }
                Some(_) => {
                    changes.replaced += 1;
                    "Replaced geo filter"
                }
            };
            info!(
                filter_id = %filter_id,
                database_path = %pool.config.database_path,
                action = ?pool.config.action,
                countries_count = pool.config.countries.len(),
                "{registered}"
            );
        }
        changes
    }

    /// Drop the filters a plan from [`Self::prepare`] does not name, and
    /// return how many there were.
    pub fn remove_unlisted(&self, plan: &GeoFilterPlan) -> usize {
        let mut removed = 0;
        self.filter_pools.retain(|filter_id, _| {
            let kept = plan.pools.contains_key(filter_id);
            if !kept {
                removed += 1;
                info!(filter_id = %filter_id, "Removed geo filter");
            }
            kept
        });
        removed
    }

    /// Register a geo filter from configuration
    pub fn register_filter(
        &self,
        filter_id: &str,
        config: GeoFilter,
    ) -> Result<(), GeoLookupError> {
        let pool = GeoFilterPool::new(config)?;
        self.filter_pools
            .insert(filter_id.to_string(), Arc::new(pool));
        debug!(filter_id = %filter_id, "Registered geo filter");
        Ok(())
    }

    /// Check a client IP against a specific filter
    pub fn check(&self, filter_id: &str, client_ip: &str) -> Option<GeoFilterResult> {
        self.filter_pools
            .get(filter_id)
            .map(|pool| pool.check(client_ip))
    }

    /// Get a reference to a filter pool
    pub fn get_pool(&self, filter_id: &str) -> Option<Arc<GeoFilterPool>> {
        self.filter_pools.get(filter_id).map(|r| r.clone())
    }

    /// Check if a filter exists
    pub fn has_filter(&self, filter_id: &str) -> bool {
        self.filter_pools.contains_key(filter_id)
    }

    /// Get all filter IDs
    pub fn filter_ids(&self) -> Vec<String> {
        self.filter_pools.iter().map(|r| r.key().clone()).collect()
    }

    /// Clear expired cache entries in all pools
    pub fn clear_expired_caches(&self) {
        for pool in self.filter_pools.iter() {
            pool.clear_expired();
        }
    }

    /// Reload a filter's database from disk
    pub fn reload_filter(&self, filter_id: &str) -> Result<(), GeoLookupError> {
        // The pool is cloned out of the map: a reference into it holds the
        // lock of its shard, which would make writes to the map wait for the
        // read of the database.
        let pool = self
            .filter_pools
            .get(filter_id)
            .map(|pool| Arc::clone(pool.value()));
        if let Some(pool) = pool {
            pool.reload_database()
        } else {
            Err(GeoLookupError::LoadError(format!(
                "Filter '{}' not found",
                filter_id
            )))
        }
    }

    /// Reload database for all filters using the given path
    pub fn reload_by_path(&self, path: &Path) -> Vec<(String, Result<(), GeoLookupError>)> {
        let mut results = Vec::new();
        for entry in self.filter_pools.iter() {
            if entry.value().database_path() == path {
                let filter_id = entry.key().clone();
                let result = entry.value().reload_database();
                results.push((filter_id, result));
            }
        }
        results
    }

    /// Get all unique database paths being used
    pub fn database_paths(&self) -> Vec<(String, PathBuf)> {
        self.filter_pools
            .iter()
            .map(|e| (e.key().clone(), e.value().database_path().to_path_buf()))
            .collect()
    }

    /// The periodic check: reload the database of every filter whose file
    /// changed and has stayed as it is since the previous call (see
    /// [`GeoFilterPool::reload_if_file_changed`]).
    ///
    /// Returns the filters whose database was read again, in the order of
    /// their ids, with the result for each. Opens databases, which blocks on
    /// file reads.
    pub fn reload_changed_files(&self) -> Vec<(String, Result<(), GeoLookupError>)> {
        let mut pools: Vec<(String, Arc<GeoFilterPool>)> = self
            .filter_pools
            .iter()
            .map(|e| (e.key().clone(), Arc::clone(e.value())))
            .collect();
        pools.sort_by(|(a, _), (b, _)| a.cmp(b));
        pools
            .into_iter()
            .filter_map(|(filter_id, pool)| {
                pool.reload_if_file_changed()
                    .map(|result| (filter_id, result))
            })
            .collect()
    }
}

impl Default for GeoFilterManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// GeoDatabaseWatcher
// =============================================================================

/// The databases the watcher is told about, by the directory they are in and
/// then their file name. The directory is as the system names it (see
/// [`watch_target`]); a file maps to the paths the filters give it, which can
/// be more than one.
type WatchedDirectories = HashMap<PathBuf, HashMap<OsString, Vec<PathBuf>>>;

/// The directory to watch for the database file at `path`, and the name of
/// the file in it.
///
/// The directory is resolved: through links, and for a path with no directory
/// to the working directory. The system reports the files that change under
/// the name it knows their directory by (on macOS `/var` is `/private/var`),
/// which can differ from the one the configuration uses.
fn watch_target(path: &Path) -> std::io::Result<(PathBuf, OsString)> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the path has no file name",
        )
    })?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok((std::fs::canonicalize(directory)?, name.to_os_string()))
}

/// The paths of an event that are a reason to read a database again: a file
/// that was created or written to, and a file that was renamed to the name it
/// now has. A file that was renamed to another name, or removed, is not: the
/// database in use stays until a file is put in its place.
///
/// The inotify watcher reports one rename as three events: `Name(From)` for
/// the old path, `Name(To)` for the new one, and `Name(Both)` for both, the
/// old path first. The others report `Name(Any)`, for either path.
fn changed_paths(event: &Event) -> &[PathBuf] {
    match event.kind {
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => &[],
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => match event.paths.last() {
            Some(new_path) => std::slice::from_ref(new_path),
            None => &[],
        },
        EventKind::Create(_) | EventKind::Modify(_) => &event.paths,
        _ => &[],
    }
}

/// The paths the filters give to the file that an event is about, if it is
/// one of the databases in a watched directory.
fn databases_of_event(watched: &WatchedDirectories, event_path: &Path) -> Vec<PathBuf> {
    let (Some(directory), Some(name)) = (event_path.parent(), event_path.file_name()) else {
        return Vec::new();
    };
    watched
        .get(directory)
        .and_then(|files| files.get(name))
        .cloned()
        .unwrap_or_default()
}

/// Watches geo database files for changes and triggers reloads
///
/// A database file is not watched itself but the directory it is in: a file
/// that is replaced by renaming a new one over it is a different file under
/// the same name, and a watch on the old one ends with it.
pub struct GeoDatabaseWatcher {
    /// The watcher instance; none while there is no database to watch
    watcher: RwLock<Option<notify::RecommendedWatcher>>,
    /// Mapping from database path to filter IDs using it
    path_to_filters: RwLock<HashMap<PathBuf, Vec<String>>>,
    /// The directories `watcher` is watching, and the databases in them.
    /// Shared with the function `watcher` calls for each event.
    watched: Arc<RwLock<WatchedDirectories>>,
    /// Where `watcher` reports the paths that changed; set by
    /// [`Self::start_watching`]
    events: RwLock<Option<mpsc::Sender<PathBuf>>>,
    /// Reference to the geo filter manager
    manager: Arc<GeoFilterManager>,
}

impl GeoDatabaseWatcher {
    /// Create a new database watcher
    pub fn new(manager: Arc<GeoFilterManager>) -> Self {
        Self {
            watcher: RwLock::new(None),
            path_to_filters: RwLock::new(HashMap::new()),
            watched: Arc::new(RwLock::new(HashMap::new())),
            events: RwLock::new(None),
            manager,
        }
    }

    /// Start watching all registered database files
    ///
    /// The receiver gets the path, as the filters name it, of each database
    /// file that changed: one that was created, written to or renamed, not
    /// one that was removed. It stays open while there is nothing to watch: a
    /// later [`Self::sync_watches`] can add databases. [`Self::run`] reads
    /// the receiver.
    pub fn start_watching(&self) -> Result<mpsc::Receiver<PathBuf>, GeoLookupError> {
        let (tx, rx) = mpsc::channel::<PathBuf>(10);
        *self.events.write() = Some(tx);
        if let Err(e) = self.sync_watches() {
            // Nothing reads the receiver: later calls must not watch either.
            *self.events.write() = None;
            return Err(e);
        }
        Ok(rx)
    }

    /// Make the watched directories those of the database files of the
    /// manager's filters as they are now: watch the ones it has gained and
    /// stop watching the ones it has lost. Databases in one directory share
    /// its watch, which ends with the last of them.
    ///
    /// Does nothing before [`Self::start_watching`]. A file whose directory
    /// cannot be watched is logged and tried again by the next call.
    ///
    /// # Errors
    ///
    /// Fails when there are files to watch and the file watcher cannot be
    /// created.
    pub fn sync_watches(&self) -> Result<(), GeoLookupError> {
        let Some(tx) = self.events.read().clone() else {
            return Ok(());
        };

        // Build path → filter ID mapping
        let mut path_map: HashMap<PathBuf, Vec<String>> = HashMap::new();
        for (filter_id, path) in self.manager.database_paths() {
            path_map.entry(path).or_default().push(filter_id);
        }

        // Holding the watcher serialises calls.
        let mut watcher_slot = self.watcher.write();

        if path_map.is_empty() {
            debug!("No geo databases to watch");
            *self.path_to_filters.write() = path_map;
            if watcher_slot.take().is_some() {
                info!("Stopped watching geo database files");
            }
            self.watched.write().clear();
            return Ok(());
        }

        // Store the mapping, so a change to a file watched from here on is
        // known to the filters using it.
        *self.path_to_filters.write() = path_map.clone();

        if watcher_slot.is_none() {
            // Create file watcher
            let watched = Arc::clone(&self.watched);
            let watcher =
                notify::recommended_watcher(move |event: Result<Event, notify::Error>| {
                    let event = match event {
                        Ok(event) => event,
                        Err(e) => {
                            warn!(error = %e, "Geo database file watcher error");
                            return;
                        }
                    };
                    for path in changed_paths(&event) {
                        // The lock is not held while sending, which can wait.
                        let databases = databases_of_event(&watched.read(), path);
                        for database in databases {
                            let _ = tx.blocking_send(database);
                        }
                    }
                })
                .map_err(|e| {
                    GeoLookupError::LoadError(format!("Failed to create file watcher: {}", e))
                })?;
            *watcher_slot = Some(watcher);
        }
        let Some(watcher) = watcher_slot.as_mut() else {
            return Ok(());
        };

        // The directories of the databases, and the databases in each
        let mut wanted: WatchedDirectories = HashMap::new();
        for path in path_map.keys() {
            match watch_target(path) {
                Ok((directory, name)) => {
                    wanted
                        .entry(directory)
                        .or_default()
                        .entry(name)
                        .or_default()
                        .push(path.clone());
                }
                Err(e) => warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to find the directory of a geo database file to watch"
                ),
            }
        }

        // The lock on what is watched is not held while the watcher is told
        // about directories: some watchers (inotify) answer on the thread that
        // takes that lock for each event.
        let before = self.watched_paths();
        let watched_directories: HashSet<PathBuf> = self.watched.read().keys().cloned().collect();
        let added: Vec<PathBuf> = wanted
            .keys()
            .filter(|directory| !watched_directories.contains(*directory))
            .cloned()
            .collect();
        let removed: Vec<PathBuf> = watched_directories
            .iter()
            .filter(|directory| !wanted.contains_key(*directory))
            .cloned()
            .collect();

        // The databases of the new directories are known before the directories
        // are watched, so that no event of one is dropped for not being. One
        // that cannot be watched is taken out again below.
        *self.watched.write() = wanted;

        // Stop watching the directories no filter uses any more
        for directory in &removed {
            if let Err(e) = watcher.unwatch(directory) {
                debug!(
                    directory = %directory.display(),
                    error = %e,
                    "Failed to stop watching geo database directory"
                );
            }
        }

        // Watch each directory not watched yet
        for directory in &added {
            if let Err(e) = watcher.watch(directory, RecursiveMode::NonRecursive) {
                warn!(
                    directory = %directory.display(),
                    error = %e,
                    "Failed to watch geo database directory"
                );
                self.watched.write().remove(directory);
            } else {
                debug!(
                    directory = %directory.display(),
                    "Watching geo database directory"
                );
            }
        }

        let after = self.watched_paths();
        for path in before.difference(&after) {
            info!(
                path = %path.display(),
                "Stopped watching geo database"
            );
        }
        for path in after.difference(&before) {
            info!(
                path = %path.display(),
                "Watching geo database for changes"
            );
        }

        Ok(())
    }

    /// The database files being watched, as the filters name them
    pub fn watched_paths(&self) -> HashSet<PathBuf> {
        self.watched
            .read()
            .values()
            .flat_map(|files| files.values().flatten())
            .cloned()
            .collect()
    }

    /// The directories being watched, as the system names them
    #[cfg(test)]
    pub(crate) fn watched_directories(&self) -> HashSet<PathBuf> {
        self.watched.read().keys().cloned().collect()
    }

    /// Handle a file change event
    ///
    /// Reads the databases on the calling thread, which waits for the file
    /// reads. [`Self::run`] reads them on a thread for blocking work instead.
    pub fn handle_change(&self, path: &Path) {
        // The lock is not held while the databases are read, which takes a
        // while and which `sync_watches` waits for the lock to follow.
        let filter_ids = self.path_to_filters.read().get(path).cloned();
        if let Some(filter_ids) = filter_ids {
            reload_filters_of_file(&self.manager, path, &filter_ids);
        }
    }

    /// Run `work`, which reads databases, on a thread for blocking work, and
    /// wait for it, so that the worker thread this task runs on is free to run
    /// other tasks meanwhile. Returns none, after logging it, when `work` does
    /// not finish: when it panics, in a build where panics unwind, or when the
    /// runtime is shutting down.
    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&GeoFilterManager) -> T + Send + 'static,
    ) -> Option<T> {
        let manager = Arc::clone(&self.manager);
        match tokio::task::spawn_blocking(move || work(&manager)).await {
            Ok(done) => Some(done),
            Err(e) => {
                error!(
                    error = %e,
                    "Reading the geo databases did not finish; the watcher goes on"
                );
                None
            }
        }
    }

    /// Read the databases again as their files change, until `events` ends.
    ///
    /// The paths come from [`Self::start_watching`]. One that arrives is
    /// held until `settle` has gone by with no other arriving, so that a file
    /// written in steps, or several files changing together, are read when
    /// they are done. Every path held is then read again, once; none is
    /// dropped. Files that do not stop changing are not waited for for ever:
    /// the wait ends at 20 times `settle`, and what changed by then is read.
    ///
    /// Every `poll_interval` the files are looked at as well, whether or not
    /// an event came (see [`GeoFilterManager::reload_changed_files`]): a
    /// watch can miss a change, as when the directory itself is replaced or
    /// the system has no more watches to give.
    ///
    /// The databases are read on a thread for blocking work, and this waits
    /// for it: one batch at a time, either the files of the paths held or the
    /// files the periodic check finds changed. A slow read holds up the next
    /// one, and a path that arrives meanwhile waits in `events`, but the other
    /// tasks of the runtime go on. A read that does not finish (one that
    /// panics, in a build where panics unwind) is logged, and this goes on.
    ///
    /// # Panics
    ///
    /// Panics if `poll_interval` is zero.
    pub async fn run(
        &self,
        mut events: mpsc::Receiver<PathBuf>,
        settle: Duration,
        poll_interval: Duration,
    ) {
        let mut poll = tokio::time::interval(poll_interval);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first tick is immediate, and the files were opened just now.
        poll.tick().await;

        loop {
            tokio::select! {
                first = events.recv() => {
                    let Some(first) = first else {
                        return;
                    };
                    let mut changed = BTreeSet::from([first]);
                    // Each path that arrives starts the wait over, but the wait
                    // as a whole has a limit: files that never stop changing
                    // are read all the same.
                    let limit = tokio::time::Instant::now()
                        + settle.saturating_mul(SETTLE_LIMIT_FACTOR);
                    loop {
                        let now = tokio::time::Instant::now();
                        if now >= limit {
                            warn!(
                                changed = changed.len(),
                                limit_ms = settle.saturating_mul(SETTLE_LIMIT_FACTOR).as_millis() as u64,
                                "Geo database files did not stop changing, reading what changed so far"
                            );
                            break;
                        }
                        match tokio::time::timeout_at((now + settle).min(limit), events.recv())
                            .await
                        {
                            Ok(Some(path)) => {
                                changed.insert(path);
                            }
                            // Quiet for `settle`, or no more events.
                            _ => break,
                        }
                    }
                    // Which filters read each file is looked up here, quickly;
                    // the reading is what waits.
                    let reloads: Vec<(PathBuf, Vec<String>)> = changed
                        .into_iter()
                        .filter_map(|path| {
                            let filter_ids = self.path_to_filters.read().get(&path).cloned()?;
                            Some((path, filter_ids))
                        })
                        .collect();
                    if !reloads.is_empty() {
                        self.blocking(move |manager| {
                            for (path, filter_ids) in &reloads {
                                reload_filters_of_file(manager, path, filter_ids);
                            }
                        })
                        .await;
                    }
                }
                _ = poll.tick() => {
                    let reloaded = self
                        .blocking(|manager| manager.reload_changed_files())
                        .await;
                    if let Some(reloaded) = reloaded {
                        for (filter_id, result) in reloaded {
                            log_reload(&filter_id, result);
                        }
                    }
                }
            }
        }
    }

    /// Stop watching
    pub fn stop(&self) {
        *self.events.write() = None;
        *self.watcher.write() = None;
        self.watched.write().clear();
        info!("Stopped watching geo database files");
    }
}

/// How many times `settle` [`GeoDatabaseWatcher::run`] waits at most for the
/// changes to a database to settle.
const SETTLE_LIMIT_FACTOR: u32 = 20;

/// Read again the databases of the filters `filter_ids`, which use the file at
/// `path`, which changed. Waits for the file reads.
fn reload_filters_of_file(manager: &GeoFilterManager, path: &Path, filter_ids: &[String]) {
    info!(
        path = %path.display(),
        filters = ?filter_ids,
        "Geo database file changed, reloading"
    );

    for filter_id in filter_ids {
        log_reload(filter_id, manager.reload_filter(filter_id));
    }
}

/// Log how the reload of a filter's database went.
fn log_reload(filter_id: &str, result: Result<(), GeoLookupError>) {
    match result {
        Ok(()) => {
            info!(
                filter_id = %filter_id,
                "Geo filter database reloaded successfully"
            );
        }
        Err(e) => {
            error!(
                filter_id = %filter_id,
                error = %e,
                "Failed to reload geo filter database; the database in use stays"
            );
        }
    }
}

// =============================================================================
// Test database
// =============================================================================

/// A MaxMind database file for tests.
#[cfg(test)]
pub(crate) mod test_database {
    use std::path::Path;

    fn string(s: &str) -> Vec<u8> {
        assert!(s.len() < 29);
        let mut out = vec![0x40 | s.len() as u8];
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        assert!(entries.len() < 29);
        let mut out = vec![0xE0 | entries.len() as u8];
        for (key, value) in entries {
            out.extend(string(key));
            out.extend_from_slice(value);
        }
        out
    }

    fn uint16(n: u16) -> Vec<u8> {
        let mut out = vec![0xA2];
        out.extend_from_slice(&n.to_be_bytes());
        out
    }

    fn uint32(n: u32) -> Vec<u8> {
        let mut out = vec![0xC4];
        out.extend_from_slice(&n.to_be_bytes());
        out
    }

    /// An extended type: the control byte carries the size, the next byte the
    /// type minus 7.
    fn uint64(n: u64) -> Vec<u8> {
        let mut out = vec![0x08, 0x02];
        out.extend_from_slice(&n.to_be_bytes());
        out
    }

    fn array(items: &[Vec<u8>]) -> Vec<u8> {
        assert!(items.len() < 29);
        let mut out = vec![items.len() as u8, 0x04];
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    /// Write a database to `path` that says every IPv4 address is in
    /// `country`.
    ///
    /// Its search tree is one node whose two records both point at the one
    /// record of the data section.
    pub(crate) fn write_country_database(path: &Path, country: &str) {
        std::fs::write(path, country_database(country, 4, 0)).expect("write the test database");
    }

    /// As [`write_country_database`], for a database of IP version 6, which
    /// says every address, of either version, is in `country`.
    pub(crate) fn write_country_database_v6(path: &Path, country: &str) {
        std::fs::write(path, country_database(country, 6, 0)).expect("write the test database");
    }

    /// As [`write_country_database`], but the records of the search tree
    /// point far beyond the end of the data section, so a lookup of any
    /// address fails.
    pub(crate) fn write_dangling_database(path: &Path) {
        std::fs::write(path, country_database("US", 4, 1000)).expect("write the test database");
    }

    fn country_database(country: &str, ip_version: u16, record_offset: u32) -> Vec<u8> {
        const NODE_COUNT: u32 = 1;
        // A record past the node count points into the data section, after
        // the 16 bytes that separate the two.
        let record = (NODE_COUNT + 16 + record_offset).to_be_bytes();

        let mut file = Vec::new();
        file.extend_from_slice(&record[1..]);
        file.extend_from_slice(&record[1..]);
        file.extend_from_slice(&[0; 16]);
        file.extend(map(&[("country", map(&[("iso_code", string(country))]))]));
        file.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        file.extend(map(&[
            ("binary_format_major_version", uint16(2)),
            ("binary_format_minor_version", uint16(0)),
            ("build_epoch", uint64(1_700_000_000)),
            ("database_type", string("Test-Country")),
            ("description", map(&[])),
            ("ip_version", uint16(ip_version)),
            ("languages", array(&[string("en")])),
            ("node_count", uint32(NODE_COUNT)),
            ("record_size", uint16(24)),
        ]));
        file
    }

    /// An IP2Location DB1 (country only) file, as bytes.
    ///
    /// The IPv4 addresses are in three ranges, from 0.0.0.0, 64.0.0.0 and
    /// 128.0.0.0, which `countries` names in turn. With `ipv6`, there is an
    /// IPv6 table too: `::` to `2fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff` is in
    /// the first country and the rest in the last. Without it, the header says
    /// there are no IPv6 rows and where they would start is 0.
    ///
    /// The layout is the header, the IPv4 rows, the IPv6 rows and then the
    /// country strings, so the last byte of the file is the end of the name of
    /// the last country. The reader finds a row from its 1-based address in
    /// the header, and a country from the position of its string in the file;
    /// see `ip2location-0.6.1/src/ip2location/db.rs` (`read_header`,
    /// `ipv4_lookup`, `ipv6_lookup`, `read_record`).
    pub(crate) fn ip2location_country_database(countries: [&str; 3], ipv6: bool) -> Vec<u8> {
        const HEADER_LEN: usize = 64;
        // Each range starts at the address given here, and the last row only
        // ends the one before it.
        const IPV4_ROWS: [u32; 4] = [0, 0x4000_0000, 0x8000_0000, u32::MAX];
        const IPV6_ROWS: [u128; 3] = [0, 0x3000 << 112, u128::MAX];
        // A row is the address its range starts at, then the position of the
        // string of its country (IPv4: 4 + 4 bytes; IPv6: 16 + 4 bytes).
        const IPV4_ROW_LEN: usize = 8;
        const IPV6_ROW_LEN: usize = 20;

        let ipv4_table = HEADER_LEN;
        let ipv6_table = ipv4_table + IPV4_ROWS.len() * IPV4_ROW_LEN;
        let strings = if ipv6 {
            ipv6_table + IPV6_ROWS.len() * IPV6_ROW_LEN
        } else {
            ipv6_table
        };

        // A country is its code and its name, each behind its length.
        let mut country_strings = Vec::new();
        let mut positions = [0u32; 3];
        for (position, code) in positions.iter_mut().zip(countries) {
            *position = u32::try_from(strings + country_strings.len()).expect("small file");
            let name = format!("Country {code}");
            country_strings.push(code.len() as u8);
            country_strings.extend_from_slice(code.as_bytes());
            country_strings.push(name.len() as u8);
            country_strings.extend_from_slice(name.as_bytes());
        }

        let mut file = vec![0u8; HEADER_LEN];
        for (i, from) in IPV4_ROWS.iter().enumerate() {
            file.extend_from_slice(&from.to_le_bytes());
            file.extend_from_slice(&positions[i.min(2)].to_le_bytes());
        }
        if ipv6 {
            for (from, country) in IPV6_ROWS.iter().zip([0, 2, 2]) {
                // The reader takes an address from its bytes in reverse.
                file.extend_from_slice(&from.to_le_bytes());
                file.extend_from_slice(&positions[country].to_le_bytes());
            }
        }
        file.extend(country_strings);

        let one_based = |at: usize| u32::try_from(at + 1).expect("small file").to_le_bytes();
        file[0] = 1; // database type: DB1
        file[1] = 2; // columns in a row: the address and the country
        file[2..5].copy_from_slice(&[24, 1, 1]); // year, month, day
        file[5..9].copy_from_slice(&3u32.to_le_bytes()); // IPv4 rows
        file[9..13].copy_from_slice(&one_based(ipv4_table));
        if ipv6 {
            file[13..17].copy_from_slice(&2u32.to_le_bytes()); // IPv6 rows
            file[17..21].copy_from_slice(&one_based(ipv6_table));
        }
        // No index tables: bytes 21..29 stay 0.
        file[29] = 1; // product code: IP2Location
        let len = u32::try_from(file.len()).expect("small file");
        file[31..35].copy_from_slice(&len.to_le_bytes());
        file
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::{GeoDatabaseType, GeoFailureMode, GeoFilter, GeoFilterAction};

    // =========================================================================
    // Mock GeoDatabase
    // =========================================================================

    /// Mock database that returns pre-configured country codes for IPs.
    struct MockGeoDatabase {
        mapping: HashMap<IpAddr, String>,
        fail_on: HashSet<IpAddr>,
    }

    impl MockGeoDatabase {
        fn new() -> Self {
            Self {
                mapping: HashMap::new(),
                fail_on: HashSet::new(),
            }
        }

        fn with_entries(entries: Vec<(&str, &str)>) -> Self {
            let mut db = Self::new();
            for (ip, country) in entries {
                db.mapping.insert(ip.parse().unwrap(), country.to_string());
            }
            db
        }

        fn with_failure(mut self, ip: &str) -> Self {
            self.fail_on.insert(ip.parse().unwrap());
            self
        }
    }

    impl GeoDatabase for MockGeoDatabase {
        fn lookup(&self, ip: IpAddr) -> Result<Option<String>, GeoLookupError> {
            if self.fail_on.contains(&ip) {
                return Err(GeoLookupError::DatabaseError("mock failure".to_string()));
            }
            Ok(self.mapping.get(&ip).cloned())
        }

        fn database_type(&self) -> GeoDatabaseType {
            GeoDatabaseType::MaxMind
        }
    }

    fn mock_pool(
        action: GeoFilterAction,
        countries: Vec<&str>,
        on_failure: GeoFailureMode,
        db: MockGeoDatabase,
    ) -> GeoFilterPool {
        let config = GeoFilter {
            database_path: "/mock/db.mmdb".to_string(),
            database_type: Some(GeoDatabaseType::MaxMind),
            action,
            countries: countries.into_iter().map(|s| s.to_string()).collect(),
            on_failure,
            status_code: 403,
            block_message: Some("Blocked by geo filter".to_string()),
            cache_ttl_secs: 300,
            add_country_header: true,
        };
        GeoFilterPool::new_with_database(config, Arc::new(db))
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_geo_lookup_error_display() {
        let err = GeoLookupError::InvalidIp("not-an-ip".to_string());
        assert!(err.to_string().contains("invalid IP"));

        let err = GeoLookupError::DatabaseError("db error".to_string());
        assert!(err.to_string().contains("database error"));

        let err = GeoLookupError::LoadError("load error".to_string());
        assert!(err.to_string().contains("failed to load"));
    }

    // =========================================================================
    // Block Mode Tests (blocklist)
    // =========================================================================

    #[test]
    fn block_mode_blocks_listed_country() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN"), ("5.6.7.8", "US")]);
        let pool = mock_pool(
            GeoFilterAction::Block,
            vec!["CN", "RU"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(!result.allowed, "CN should be blocked");
        assert_eq!(result.country_code, Some("CN".to_string()));
        assert_eq!(result.status_code, 403);
    }

    #[test]
    fn block_mode_allows_unlisted_country() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN"), ("5.6.7.8", "US")]);
        let pool = mock_pool(
            GeoFilterAction::Block,
            vec!["CN", "RU"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("5.6.7.8");
        assert!(result.allowed, "US should be allowed");
        assert_eq!(result.country_code, Some("US".to_string()));
    }

    #[test]
    fn block_mode_allows_unknown_ip() {
        let db = MockGeoDatabase::new(); // Empty database
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let result = pool.check("10.0.0.1");
        assert!(result.allowed, "Unknown IP should be allowed in block mode");
        assert_eq!(result.country_code, None);
    }

    // =========================================================================
    // Allow Mode Tests (allowlist)
    // =========================================================================

    #[test]
    fn allow_mode_allows_listed_country() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US"), ("5.6.7.8", "GB")]);
        let pool = mock_pool(
            GeoFilterAction::Allow,
            vec!["US", "GB", "CA"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(result.allowed, "US should be allowed");

        let result = pool.check("5.6.7.8");
        assert!(result.allowed, "GB should be allowed");
    }

    #[test]
    fn allow_mode_blocks_unlisted_country() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN")]);
        let pool = mock_pool(
            GeoFilterAction::Allow,
            vec!["US", "GB"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(!result.allowed, "CN should be blocked in allow mode");
    }

    #[test]
    fn allow_mode_blocks_unknown_ip() {
        let db = MockGeoDatabase::new();
        let pool = mock_pool(GeoFilterAction::Allow, vec!["US"], GeoFailureMode::Open, db);

        let result = pool.check("10.0.0.1");
        assert!(!result.allowed, "Unknown IP blocked when allowlist is set");
    }

    #[test]
    fn allow_mode_allows_nobody_when_empty_list() {
        // The configuration refuses this combination; a pool built without
        // it must not read the empty list as "everybody".
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN")]);
        let pool = mock_pool(
            GeoFilterAction::Allow,
            vec![], // Empty countries list
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(!result.allowed, "Empty allow list should allow nobody");
    }

    // =========================================================================
    // Log-Only Mode Tests
    // =========================================================================

    #[test]
    fn log_only_mode_never_blocks() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN")]);
        let pool = mock_pool(
            GeoFilterAction::LogOnly,
            vec!["CN"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(result.allowed, "Log-only mode should never block");
        assert_eq!(result.country_code, Some("CN".to_string()));
    }

    // =========================================================================
    // Failure Mode Tests
    // =========================================================================

    #[test]
    fn fail_open_allows_on_lookup_error() {
        let db = MockGeoDatabase::new().with_failure("1.2.3.4");
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let result = pool.check("1.2.3.4");
        assert!(result.allowed, "Fail-open should allow on error");
        assert_eq!(result.country_code, None);
    }

    #[test]
    fn fail_closed_blocks_on_lookup_error() {
        let db = MockGeoDatabase::new().with_failure("1.2.3.4");
        let pool = mock_pool(
            GeoFilterAction::Block,
            vec!["CN"],
            GeoFailureMode::Closed,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(!result.allowed, "Fail-closed should block on error");
    }

    #[test]
    fn fail_open_allows_on_invalid_ip() {
        let db = MockGeoDatabase::new();
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let result = pool.check("not-an-ip");
        assert!(result.allowed, "Fail-open should allow on invalid IP");
    }

    #[test]
    fn fail_closed_blocks_on_invalid_ip() {
        let db = MockGeoDatabase::new();
        let pool = mock_pool(
            GeoFilterAction::Block,
            vec!["CN"],
            GeoFailureMode::Closed,
            db,
        );

        let result = pool.check("not-an-ip");
        assert!(!result.allowed, "Fail-closed should block on invalid IP");
    }

    // =========================================================================
    // Cache Tests
    // =========================================================================

    #[test]
    fn cache_hit_on_repeated_lookup() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US")]);
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let first = pool.check("1.2.3.4");
        assert!(!first.cache_hit, "First lookup should be a cache miss");

        let second = pool.check("1.2.3.4");
        assert!(second.cache_hit, "Second lookup should be a cache hit");
        assert_eq!(second.country_code, Some("US".to_string()));
    }

    #[test]
    fn cache_stats_report_correctly() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US"), ("5.6.7.8", "GB")]);
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        // Initial state
        let (total, valid) = pool.cache_stats();
        assert_eq!(total, 0);
        assert_eq!(valid, 0);

        // After lookups
        pool.check("1.2.3.4");
        pool.check("5.6.7.8");

        let (total, valid) = pool.cache_stats();
        assert_eq!(total, 2);
        assert_eq!(valid, 2);
    }

    #[test]
    fn clear_expired_removes_old_entries() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US")]);
        let config = GeoFilter {
            database_path: "/mock/db.mmdb".to_string(),
            database_type: Some(GeoDatabaseType::MaxMind),
            action: GeoFilterAction::Block,
            countries: vec!["CN".to_string()],
            on_failure: GeoFailureMode::Open,
            status_code: 403,
            block_message: None,
            cache_ttl_secs: 0, // Immediate expiry
            add_country_header: true,
        };
        let pool = GeoFilterPool::new_with_database(config, Arc::new(db));

        pool.check("1.2.3.4");
        let (total, _) = pool.cache_stats();
        assert_eq!(total, 1);

        // With TTL=0, entries are expired immediately
        std::thread::sleep(Duration::from_millis(10));
        pool.clear_expired();

        let (total, _) = pool.cache_stats();
        assert_eq!(total, 0);
    }

    fn geo_pool_with_ttl(cache_ttl_secs: u64) -> GeoFilterPool {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US")]);
        let config = GeoFilter {
            database_path: "/mock/db.mmdb".to_string(),
            database_type: Some(GeoDatabaseType::MaxMind),
            action: GeoFilterAction::Block,
            countries: vec!["CN".to_string()],
            on_failure: GeoFailureMode::Open,
            status_code: 403,
            block_message: None,
            cache_ttl_secs,
            add_country_header: false,
        };
        GeoFilterPool::new_with_database(config, Arc::new(db))
    }

    /// Fills the pool's cache with `n` distinct IPv6 addresses of one /64.
    fn fill_cache(pool: &GeoFilterPool, n: usize, at: Instant) {
        for i in 0..n as u64 {
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(
                0x2001_0db8_0000_0001_0000_0000_0000_0000u128 | i as u128,
            ));
            pool.cache_result(ip, Some("US".to_string()), at);
        }
    }

    #[test]
    fn cache_stops_growing_at_its_limit() {
        let pool = geo_pool_with_ttl(3600);
        fill_cache(&pool, GEO_CACHE_MAX_ENTRIES + 1000, Instant::now());
        assert_eq!(pool.cache_stats().0, GEO_CACHE_MAX_ENTRIES);

        // A full cache still answers from the database, uncached.
        let result = pool.check("1.2.3.4");
        assert!(result.allowed);
        assert_eq!(result.country_code.as_deref(), Some("US"));
        assert!(!result.cache_hit);
        assert_eq!(pool.cache_stats().0, GEO_CACHE_MAX_ENTRIES);
    }

    #[test]
    fn full_cache_drops_expired_entries_to_make_room() {
        let pool = geo_pool_with_ttl(1);
        let old = Instant::now() - Duration::from_secs(5);
        fill_cache(&pool, GEO_CACHE_MAX_ENTRIES, old);
        assert_eq!(pool.cache_stats(), (GEO_CACHE_MAX_ENTRIES, 0));

        pool.check("1.2.3.4");
        assert_eq!(pool.cache_stats(), (1, 1));
        assert!(pool.check("1.2.3.4").cache_hit);
    }

    // =========================================================================
    // Country Header Tests
    // =========================================================================

    #[test]
    fn add_header_flag_propagated() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US")]);
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let result = pool.check("1.2.3.4");
        assert!(result.add_header, "add_country_header should be true");
    }

    // =========================================================================
    // Manager Tests
    // =========================================================================

    #[test]
    fn test_geo_filter_manager_new() {
        let manager = GeoFilterManager::new();
        assert!(manager.filter_ids().is_empty());
        assert!(!manager.has_filter("test"));
    }

    #[test]
    fn test_geo_filter_manager_check_nonexistent_filter() {
        let manager = GeoFilterManager::new();
        let result = manager.check("nonexistent", "1.2.3.4");
        assert!(result.is_none());
    }

    #[test]
    fn test_geo_filter_manager_reload_nonexistent() {
        let manager = GeoFilterManager::new();
        let result = manager.reload_filter("nonexistent");
        assert!(matches!(result, Err(GeoLookupError::LoadError(_))));
    }

    // =========================================================================
    // GeoFilterManager::from_config
    // =========================================================================

    fn config_with(filters: &str) -> Config {
        Config::from_kdl(&format!(
            r#"
            schema-version "1.0"
            system {{ worker-threads 0 }}
            listeners {{
                listener "http" {{ address "127.0.0.1:19292" protocol "http" }}
            }}
            routes {{
                route "all" {{
                    matches {{ path-prefix "/" }}
                    upstream "backend"
                }}
            }}
            upstreams {{
                upstream "backend" {{ target "127.0.0.1:19293" }}
            }}
            {filters}
            "#
        ))
        .expect("config parses")
    }

    fn geo(id: &str, path: &str) -> String {
        format!(
            r#"filter "{id}" {{
                type "geo"
                database-path "{path}"
                countries "RU" "CN"
            }}"#
        )
    }

    fn failure(config: &Config) -> String {
        match GeoFilterManager::from_config(config) {
            Ok(_) => panic!("a geo filter without a database must not register"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn from_config_fails_for_a_missing_database_and_names_filter_and_path() {
        let config = config_with(&format!(
            "filters {{ {} }}",
            geo("region-block", "/nonexistent/geo/country.mmdb")
        ));

        let message = failure(&config);
        assert!(message.contains("'region-block'"), "{message}");
        assert!(
            message.contains("'/nonexistent/geo/country.mmdb'"),
            "{message}"
        );
    }

    #[test]
    fn from_config_lists_every_failure_in_the_order_of_the_filter_ids() {
        // Written in the reverse of the order they are reported in.
        let config = config_with(&format!(
            "filters {{\n{}\n{}\n{}\n}}",
            geo("zz-last", "/nonexistent/geo/z.mmdb"),
            geo("mm-middle", "/nonexistent/geo/m.mmdb"),
            geo("aa-first", "/nonexistent/geo/a.mmdb"),
        ));

        let message = failure(&config);
        assert!(message.contains("3 geo filter(s)"), "{message}");
        let at = |id: &str| {
            message
                .find(id)
                .unwrap_or_else(|| panic!("{id}: {message}"))
        };
        assert!(at("'aa-first'") < at("'mm-middle'"), "{message}");
        assert!(at("'mm-middle'") < at("'zz-last'"), "{message}");
    }

    #[test]
    fn from_config_registers_nothing_when_there_is_no_geo_filter() {
        let config = config_with(
            r#"filters {
                filter "limit" {
                    type "rate-limit"
                    max-rps 10
                }
            }"#,
        );

        let manager = GeoFilterManager::from_config(&config).expect("no geo filter to open");
        assert!(manager.filter_ids().is_empty());
    }

    #[test]
    fn from_config_opens_the_geo_filters_of_namespaces_and_services() {
        let filters = format!(
            "filters {{ {} }}",
            geo("regional", "/nonexistent/geo/regional.mmdb")
        );
        let config = config_with(&format!(
            "namespace \"ns\" {{\n{filters}\nservice \"svc\" {{\n{filters}\n}}\n}}"
        ))
        .lower_scopes();

        let message = failure(&config);
        assert!(message.contains("2 geo filter(s)"), "{message}");
        assert!(message.contains("ns:regional"), "{message}");
        assert!(message.contains("ns:svc:regional"), "{message}");
    }

    #[test]
    fn a_database_whose_type_cannot_be_told_is_not_guessed_at() {
        let config = GeoFilter {
            database_path: "/nonexistent/geo/country.dat".to_string(),
            database_type: None,
            action: GeoFilterAction::Block,
            countries: vec!["CN".to_string()],
            on_failure: GeoFailureMode::Open,
            status_code: 403,
            block_message: None,
            cache_ttl_secs: 3600,
            add_country_header: true,
        };

        let message = match GeoFilterPool::new(config) {
            Ok(_) => panic!("a database of unknown type must not open"),
            Err(e) => e.to_string(),
        };
        assert!(message.contains("database-type"), "{message}");
    }

    // =========================================================================
    // GeoFilterManager::prepare and apply
    // =========================================================================

    /// A geo filter that blocks `countries` (quoted, space-separated).
    fn geo_blocking(id: &str, path: &str, countries: &str) -> String {
        format!(
            r#"filter "{id}" {{
                type "geo"
                database-path "{path}"
                countries {countries}
            }}"#
        )
    }

    fn filters_config(filters: &[String]) -> Config {
        config_with(&format!("filters {{\n{}\n}}", filters.join("\n")))
    }

    /// Builds the pool of a filter on a database that says `203.0.113.7` is
    /// in RU, unless its path says "missing", and records every path it was
    /// asked to open.
    struct Opener {
        opened: std::cell::RefCell<Vec<String>>,
    }

    impl Opener {
        fn new() -> Self {
            Self {
                opened: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn open(&self, config: GeoFilter) -> Result<GeoFilterPool, GeoLookupError> {
            self.opened.borrow_mut().push(config.database_path.clone());
            if config.database_path.contains("missing") {
                return Err(GeoLookupError::LoadError(format!(
                    "failed to open {}",
                    config.database_path
                )));
            }
            let database = MockGeoDatabase::with_entries(vec![("203.0.113.7", "RU")]);
            Ok(GeoFilterPool::new_with_database(config, Arc::new(database)))
        }

        fn opened(&self) -> Vec<String> {
            self.opened.borrow().clone()
        }
    }

    /// A manager that has registered `config`.
    fn registered(config: &Config) -> GeoFilterManager {
        let manager = GeoFilterManager::new();
        let opener = Opener::new();
        let plan = manager
            .prepare_with(config, |c| opener.open(c))
            .expect("the databases open");
        manager.apply(&plan);
        manager
    }

    /// Where `needle` is in `message`; fails the test when it is not there.
    fn position(message: &str, needle: &str) -> usize {
        message
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} is not in: {message}"))
    }

    fn sorted_ids(manager: &GeoFilterManager) -> Vec<String> {
        let mut ids = manager.filter_ids();
        ids.sort();
        ids
    }

    fn pool(manager: &GeoFilterManager, id: &str) -> Arc<GeoFilterPool> {
        manager
            .get_pool(id)
            .unwrap_or_else(|| panic!("filter {id} is not registered"))
    }

    #[test]
    fn apply_registers_the_filters_of_a_configuration() {
        let manager = GeoFilterManager::new();
        let config = filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]);
        let opener = Opener::new();

        let plan = manager
            .prepare_with(&config, |c| opener.open(c))
            .expect("the databases open");
        assert!(
            manager.filter_ids().is_empty(),
            "preparing a plan must not register anything"
        );
        let changes = manager.apply(&plan);

        assert_eq!(
            changes,
            GeoFilterChanges {
                added: 2,
                replaced: 0,
                unchanged: 0
            }
        );
        assert_eq!(sorted_ids(&manager), ["a", "b"]);
        assert!(!manager.check("a", "203.0.113.7").unwrap().allowed);
    }

    #[test]
    fn unchanged_filters_keep_their_pool_and_cache_and_are_not_opened_again() {
        let config = filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]);
        let manager = registered(&config);
        let before = pool(&manager, "a");
        before.check("203.0.113.7");
        assert_eq!(before.cache_stats(), (1, 1));

        // Nothing may be opened: the databases are not there any more.
        let plan = manager
            .prepare_with(&config, |_| {
                Err(GeoLookupError::LoadError("must not be opened".to_string()))
            })
            .expect("nothing changed, so nothing needs opening");
        let changes = manager.apply(&plan);

        assert_eq!(
            changes,
            GeoFilterChanges {
                added: 0,
                replaced: 0,
                unchanged: 2
            }
        );
        assert_eq!(manager.remove_unlisted(&plan), 0);
        let after = pool(&manager, "a");
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.cache_stats(), (1, 1), "the cache was kept");
    }

    #[test]
    fn a_filter_with_changed_settings_gets_a_new_pool_and_an_empty_cache() {
        let manager = registered(&filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]));
        let old_a = pool(&manager, "a");
        let old_b = pool(&manager, "b");
        assert!(!manager.check("a", "203.0.113.7").unwrap().allowed);

        // `a` now blocks another country; `b` is as it was.
        let changed = filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""CN""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]);
        let opener = Opener::new();
        let plan = manager
            .prepare_with(&changed, |c| opener.open(c))
            .expect("the databases open");
        assert_eq!(opener.opened(), ["/geo/a.mmdb"], "only `a` is opened");
        let changes = manager.apply(&plan);

        assert_eq!(
            changes,
            GeoFilterChanges {
                added: 0,
                replaced: 1,
                unchanged: 1
            }
        );
        let new_a = pool(&manager, "a");
        assert!(!Arc::ptr_eq(&old_a, &new_a));
        assert_eq!(new_a.cache_stats(), (0, 0), "the cache is empty");
        assert!(
            manager.check("a", "203.0.113.7").unwrap().allowed,
            "the new settings apply"
        );
        assert!(Arc::ptr_eq(&old_b, &pool(&manager, "b")));
    }

    #[test]
    fn a_filter_with_a_changed_database_path_gets_a_new_pool() {
        let manager = registered(&filters_config(&[geo_blocking(
            "a",
            "/geo/a.mmdb",
            r#""RU""#,
        )]));
        let old = pool(&manager, "a");

        let moved = filters_config(&[geo_blocking("a", "/geo/moved/a.mmdb", r#""RU""#)]);
        let opener = Opener::new();
        let plan = manager
            .prepare_with(&moved, |c| opener.open(c))
            .expect("the database opens");
        let changes = manager.apply(&plan);

        assert_eq!(changes.replaced, 1);
        let new = pool(&manager, "a");
        assert!(!Arc::ptr_eq(&old, &new));
        assert_eq!(new.database_path(), Path::new("/geo/moved/a.mmdb"));
    }

    #[test]
    fn a_filter_gone_from_the_configuration_is_removed() {
        let manager = registered(&filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]));

        let opener = Opener::new();
        let plan = manager
            .prepare_with(
                &filters_config(&[geo_blocking("a", "/geo/a.mmdb", r#""RU""#)]),
                |c| opener.open(c),
            )
            .expect("nothing needs opening");
        let changes = manager.apply(&plan);

        assert_eq!(
            changes,
            GeoFilterChanges {
                added: 0,
                replaced: 0,
                unchanged: 1
            }
        );
        assert_eq!(
            sorted_ids(&manager),
            ["a", "b"],
            "applying a plan does not drop the filters it does not name"
        );

        assert_eq!(manager.remove_unlisted(&plan), 1);
        assert_eq!(sorted_ids(&manager), ["a"]);
        assert!(manager.check("b", "203.0.113.7").is_none());
    }

    #[test]
    fn a_failure_while_preparing_changes_nothing_and_names_every_failed_filter() {
        let manager = registered(&filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]));
        let old_a = pool(&manager, "a");
        let old_b = pool(&manager, "b");

        // `a` changes and opens; `b` is gone; `c` and `d` are added, and
        // neither opens.
        let next = filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""CN""#),
            geo_blocking("d", "/geo/missing/d.mmdb", r#""RU""#),
            geo_blocking("c", "/geo/missing/c.mmdb", r#""RU""#),
        ]);
        let opener = Opener::new();
        let message = match manager.prepare_with(&next, |c| opener.open(c)) {
            Ok(_) => panic!("filters whose databases do not open must fail the plan"),
            Err(e) => format!("{e:#}"),
        };

        assert!(message.contains("2 geo filter(s)"), "{message}");
        assert!(message.contains("'/geo/missing/c.mmdb'"), "{message}");
        assert!(message.contains("'/geo/missing/d.mmdb'"), "{message}");
        assert!(
            position(&message, "'c'") < position(&message, "'d'"),
            "the filters are not listed in the order of their ids; {message}"
        );
        assert_eq!(sorted_ids(&manager), ["a", "b"]);
        assert!(Arc::ptr_eq(&old_a, &pool(&manager, "a")));
        assert!(Arc::ptr_eq(&old_b, &pool(&manager, "b")));
        assert!(!manager.check("a", "203.0.113.7").unwrap().allowed);
    }

    #[test]
    fn a_plan_that_is_dropped_changes_nothing() {
        let manager = registered(&filters_config(&[geo_blocking(
            "a",
            "/geo/a.mmdb",
            r#""RU""#,
        )]));
        let old = pool(&manager, "a");

        let opener = Opener::new();
        let plan = manager
            .prepare_with(
                &filters_config(&[geo_blocking("z", "/geo/z.mmdb", r#""RU""#)]),
                |c| opener.open(c),
            )
            .expect("the database opens");
        drop(plan);

        assert_eq!(sorted_ids(&manager), ["a"]);
        assert!(Arc::ptr_eq(&old, &pool(&manager, "a")));
    }

    #[test]
    fn check_databases_names_every_filter_whose_database_does_not_open() {
        let config = filters_config(&[
            geo_blocking("zz-last", "/nonexistent/geo/z.mmdb", r#""RU""#),
            geo_blocking("aa-first", "/nonexistent/geo/a.mmdb", r#""RU""#),
        ]);

        let message = match GeoFilterManager::check_databases(&config) {
            Ok(()) => panic!("databases that do not exist must not pass"),
            Err(e) => format!("{e:#}"),
        };

        assert!(message.contains("2 geo filter(s)"), "{message}");
        assert!(
            position(&message, "'aa-first'") < position(&message, "'zz-last'"),
            "{message}"
        );
        assert!(message.contains("'/nonexistent/geo/z.mmdb'"), "{message}");
    }

    // =========================================================================
    // GeoDatabaseWatcher::sync_watches
    // =========================================================================

    #[test]
    fn the_watched_files_follow_the_filters_of_the_manager() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = |name: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, b"database").expect("write database");
            path
        };
        let (a, b, c) = (path("a.mmdb"), path("b.mmdb"), path("c.mmdb"));
        let filter =
            |id: &str, path: &Path| geo_blocking(id, &path.display().to_string(), r#""RU""#);
        let opener = Opener::new();

        // Nothing to watch yet, then `a` and `b`.
        let manager = Arc::new(GeoFilterManager::new());
        let watcher = GeoDatabaseWatcher::new(Arc::clone(&manager));
        let _events = watcher.start_watching().expect("start watching");
        assert!(watcher.watched_paths().is_empty());

        let apply = |filters: &[String]| {
            let plan = manager
                .prepare_with(&filters_config(filters), |c| opener.open(c))
                .expect("the databases open");
            manager.apply(&plan);
            manager.remove_unlisted(&plan);
            watcher.sync_watches().expect("sync the watches");
        };
        apply(&[filter("a", &a), filter("b", &b)]);
        assert_eq!(
            watcher.watched_paths(),
            HashSet::from([a.clone(), b.clone()])
        );

        // `b` is replaced by `c`: `c` is watched and `b` is not any more.
        apply(&[filter("a", &a), filter("b", &c)]);
        assert_eq!(
            watcher.watched_paths(),
            HashSet::from([a.clone(), c.clone()])
        );

        // Two filters on one file, and `a` is no longer used.
        apply(&[filter("b", &c), filter("d", &c)]);
        assert_eq!(watcher.watched_paths(), HashSet::from([c.clone()]));

        // Nothing is left to watch.
        apply(&[]);
        assert!(watcher.watched_paths().is_empty());

        // And a filter can come back.
        apply(&[filter("a", &a)]);
        assert_eq!(watcher.watched_paths(), HashSet::from([a]));
    }

    #[test]
    fn sync_watches_does_nothing_before_watching_has_started() {
        let manager = Arc::new(GeoFilterManager::new());
        let watcher = GeoDatabaseWatcher::new(manager);
        watcher.sync_watches().expect("nothing to do");
        assert!(watcher.watched_paths().is_empty());
    }

    #[test]
    fn databases_in_one_directory_share_a_watch_that_ends_with_the_last_of_them() {
        let (one, two) = (
            tempfile::tempdir().expect("tempdir"),
            tempfile::tempdir().expect("tempdir"),
        );
        let path = |dir: &tempfile::TempDir, name: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, b"database").expect("write database");
            path
        };
        let (a, b, c) = (
            path(&one, "a.mmdb"),
            path(&one, "b.mmdb"),
            path(&two, "c.mmdb"),
        );
        let directory = |dir: &tempfile::TempDir| std::fs::canonicalize(dir.path()).unwrap();
        let filter =
            |id: &str, path: &Path| geo_blocking(id, &path.display().to_string(), r#""RU""#);
        let opener = Opener::new();

        let manager = Arc::new(GeoFilterManager::new());
        let watcher = GeoDatabaseWatcher::new(Arc::clone(&manager));
        let _events = watcher.start_watching().expect("start watching");
        let apply = |filters: &[String]| {
            let plan = manager
                .prepare_with(&filters_config(filters), |c| opener.open(c))
                .expect("the databases open");
            manager.apply(&plan);
            manager.remove_unlisted(&plan);
            watcher.sync_watches().expect("sync the watches");
        };

        apply(&[filter("a", &a), filter("b", &b), filter("c", &c)]);
        assert_eq!(
            watcher.watched_directories(),
            HashSet::from([directory(&one), directory(&two)]),
            "three files in two directories take two watches"
        );
        assert_eq!(
            watcher.watched_paths(),
            HashSet::from([a.clone(), b.clone(), c.clone()])
        );

        apply(&[filter("c", &c)]);
        assert_eq!(
            watcher.watched_directories(),
            HashSet::from([directory(&two)])
        );

        apply(&[filter("a", &a)]);
        assert_eq!(
            watcher.watched_directories(),
            HashSet::from([directory(&one)])
        );
        assert_eq!(watcher.watched_paths(), HashSet::from([a]));
    }

    #[test]
    fn an_event_is_matched_to_a_database_by_directory_and_file_name() {
        let mut watched = WatchedDirectories::new();
        watched
            .entry(PathBuf::from("/geo"))
            .or_default()
            .entry(OsString::from("a.mmdb"))
            .or_default()
            .push(PathBuf::from("/geo/../geo/a.mmdb"));

        assert_eq!(
            databases_of_event(&watched, Path::new("/geo/a.mmdb")),
            [PathBuf::from("/geo/../geo/a.mmdb")],
            "the path is the one the filter gave"
        );
        assert!(databases_of_event(&watched, Path::new("/geo/b.mmdb")).is_empty());
        assert!(databases_of_event(&watched, Path::new("/other/a.mmdb")).is_empty());
        assert!(databases_of_event(&watched, Path::new("/")).is_empty());
    }

    #[test]
    fn the_paths_of_an_event_that_are_read_again_are_those_of_files_created_or_changed() {
        use notify::event::{AccessKind, CreateKind, DataChange, MetadataKind, RemoveKind};

        let (old, new) = (
            PathBuf::from("/geo/a.mmdb.old"),
            PathBuf::from("/geo/a.mmdb"),
        );
        let event = |kind: EventKind, paths: &[&PathBuf]| {
            paths.iter().fold(Event::new(kind), |event, path| {
                event.add_path((*path).clone())
            })
        };
        let read = |event: &Event| changed_paths(event).to_vec();

        // Created or written to.
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)),
        ] {
            assert_eq!(
                read(&event(kind, &[&new])),
                std::slice::from_ref(&new),
                "{kind:?}"
            );
        }

        // One rename, as the inotify watcher reports it.
        let from = event(
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            &[&new],
        );
        assert!(read(&from).is_empty(), "the old name is not read");
        let to = event(EventKind::Modify(ModifyKind::Name(RenameMode::To)), &[&new]);
        assert_eq!(read(&to), std::slice::from_ref(&new), "the new name is");
        let both = event(
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            &[&old, &new],
        );
        assert_eq!(
            read(&both),
            std::slice::from_ref(&new),
            "only the new name of both"
        );

        // As the macOS watcher reports a rename: for either path.
        let any = event(
            EventKind::Modify(ModifyKind::Name(RenameMode::Any)),
            &[&new],
        );
        assert_eq!(read(&any), std::slice::from_ref(&new));

        // Removed, or only looked at.
        for kind in [
            EventKind::Remove(RemoveKind::File),
            EventKind::Access(AccessKind::Any),
            EventKind::Any,
        ] {
            assert!(read(&event(kind, &[&new])).is_empty(), "{kind:?}");
        }
    }

    #[test]
    fn a_database_named_without_a_directory_is_looked_for_in_the_working_directory() {
        // The tests run in the crate's directory.
        let (directory, name) = watch_target(Path::new("Cargo.toml")).expect("a target");
        assert_eq!(directory, std::fs::canonicalize(".").unwrap());
        assert_eq!(name, std::ffi::OsString::from("Cargo.toml"));
    }

    // =========================================================================
    // Databases that are opened from real files
    // =========================================================================

    fn bin(countries: [&str; 3], ipv6: bool) -> Vec<u8> {
        test_database::ip2location_country_database(countries, ipv6)
    }

    fn country_of(database: &dyn GeoDatabase, ip: &str) -> Option<String> {
        database
            .lookup(ip.parse().unwrap())
            .unwrap_or_else(|e| panic!("{ip}: {e}"))
    }

    #[test]
    fn an_ip2location_file_opens_and_names_the_country_of_each_range() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        for ipv6 in [false, true] {
            std::fs::write(&path, bin(["US", "DE", "FR"], ipv6)).unwrap();
            let database = Ip2LocationDatabase::open(&path).expect("a whole file opens");

            assert_eq!(country_of(&database, "0.0.0.0").as_deref(), Some("US"));
            assert_eq!(country_of(&database, "64.0.0.1").as_deref(), Some("DE"));
            assert_eq!(country_of(&database, "192.0.2.1").as_deref(), Some("FR"));
            if ipv6 {
                assert_eq!(country_of(&database, "2001:db8::1").as_deref(), Some("US"));
                assert_eq!(country_of(&database, "3fff::1").as_deref(), Some("FR"));
            }
        }
    }

    #[test]
    fn an_ip2location_file_that_is_cut_short_does_not_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        for ipv6 in [false, true] {
            let whole = bin(["US", "DE", "FR"], ipv6);
            for len in 0..whole.len() {
                std::fs::write(&path, &whole[..len]).unwrap();
                assert!(
                    Ip2LocationDatabase::open(&path).is_err(),
                    "the first {len} of {} bytes of a file (IPv6 rows: {ipv6}) opened",
                    whole.len()
                );
            }
        }
    }

    /// `file` with the size its header records, and the product code, set.
    fn with_header(mut file: Vec<u8>, product_code: u8, recorded_size: usize) -> Vec<u8> {
        file[29] = product_code;
        file[31..35].copy_from_slice(&u32::try_from(recorded_size).unwrap().to_le_bytes());
        file
    }

    #[test]
    fn an_ip2location_file_shorter_than_its_header_records_does_not_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        let whole = bin(["US", "DE", "FR"], true);
        // Every lookup the trial makes would succeed: only the size says that
        // the file is not whole.
        std::fs::write(&path, with_header(whole.clone(), 1, whole.len() + 7)).unwrap();

        let message = match Ip2LocationDatabase::open(&path) {
            Ok(_) => panic!("a file shorter than its header says opened"),
            Err(e) => e.to_string(),
        };
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("cut short"), "{message}");
        assert!(message.contains(&whole.len().to_string()), "{message}");
        assert!(
            message.contains(&(whole.len() + 7).to_string()),
            "{message}"
        );
    }

    #[test]
    fn the_recorded_size_is_not_checked_for_the_legacy_product_code_or_a_record_of_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        let whole = bin(["US", "DE", "FR"], true);

        std::fs::write(&path, with_header(whole.clone(), 0, whole.len() + 7)).unwrap();
        Ip2LocationDatabase::open(&path).expect("product code 0 is not checked");

        std::fs::write(&path, with_header(whole.clone(), 1, 0)).unwrap();
        Ip2LocationDatabase::open(&path).expect("a size of 0 is not checked");

        // A file longer than its header says is not cut short.
        std::fs::write(&path, with_header(whole.clone(), 1, whole.len() - 1)).unwrap();
        Ip2LocationDatabase::open(&path).expect("a longer file is not checked");
    }

    #[test]
    fn a_cut_short_ip2location_file_whose_size_record_matches_fails_the_trial_lookups() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        for ipv6 in [false, true] {
            let whole = bin(["US", "DE", "FR"], ipv6);
            // From the end of the header, where the file can be mapped.
            for len in 35..whole.len() {
                std::fs::write(&path, with_header(whole[..len].to_vec(), 1, len)).unwrap();
                let message = match Ip2LocationDatabase::open(&path) {
                    Ok(_) => panic!(
                        "the first {len} of {} bytes of a file (IPv6 rows: {ipv6}) opened",
                        whole.len()
                    ),
                    Err(e) => e.to_string(),
                };
                assert!(message.contains(&path.display().to_string()), "{message}");
                assert!(message.contains("trial lookup"), "{message}");
            }
        }
    }

    #[test]
    fn a_maxmind_database_of_ip_version_6_opens_and_answers_for_both_versions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.mmdb");
        test_database::write_country_database_v6(&path, "US");

        let database = MaxMindDatabase::open(&path).expect("the database opens");
        assert_eq!(country_of(&database, "2001:db8::1").as_deref(), Some("US"));
        assert_eq!(country_of(&database, "192.0.2.1").as_deref(), Some("US"));
    }

    #[test]
    fn a_maxmind_database_whose_records_point_outside_its_data_does_not_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.mmdb");
        test_database::write_dangling_database(&path);

        let message = match MaxMindDatabase::open(&path) {
            Ok(_) => panic!("a database whose records point outside its data opened"),
            Err(e) => e.to_string(),
        };
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("trial lookup"), "{message}");
    }

    // =========================================================================
    // Files that change
    // =========================================================================

    /// A manager with one geo filter, `region`, on the database at `path`.
    fn region_manager(path: &Path) -> Arc<GeoFilterManager> {
        let config = filters_config(&[geo_blocking(
            "region",
            &path.display().to_string(),
            r#""RU""#,
        )]);
        Arc::new(GeoFilterManager::from_config(&config).expect("the database opens"))
    }

    /// The country the filter `region` finds for an address in the third
    /// range of a database from [`bin`].
    fn region_country(manager: &GeoFilterManager) -> Option<String> {
        manager
            .check("region", "192.0.2.1")
            .expect("the filter is registered")
            .country_code
    }

    /// Replace the file as an update tool does: write the new one next to it,
    /// then rename it over the old one.
    fn replace_file(path: &Path, contents: &[u8]) {
        let next = path.with_file_name("next.tmp");
        std::fs::write(&next, contents).expect("write the new file");
        std::fs::rename(&next, path).expect("rename over the old file");
    }

    async fn eventually(check: impl Fn() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        check()
    }

    #[test]
    fn the_periodic_check_reloads_a_file_that_changed_and_has_stayed_as_it_is() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        std::fs::write(&path, bin(["AA", "BB", "US"], false)).unwrap();
        let manager = region_manager(&path);
        assert_eq!(region_country(&manager).as_deref(), Some("US"));
        assert!(manager.reload_changed_files().is_empty(), "nothing changed");

        replace_file(&path, &bin(["AA", "BB", "DE"], false));
        assert!(
            manager.reload_changed_files().is_empty(),
            "a change is not read until the file has stayed as it is for a check"
        );
        let reloaded = manager.reload_changed_files();
        assert_eq!(reloaded.len(), 1, "the file stayed as it is: {reloaded:?}");
        assert_eq!(reloaded[0].0, "region");
        assert!(reloaded[0].1.is_ok(), "{reloaded:?}");
        assert_eq!(region_country(&manager).as_deref(), Some("DE"));

        assert!(
            manager.reload_changed_files().is_empty(),
            "the file has not changed since it was read"
        );
    }

    #[test]
    fn a_file_read_again_for_an_event_is_not_read_again_by_the_periodic_check() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        std::fs::write(&path, bin(["AA", "BB", "US"], false)).unwrap();
        let manager = region_manager(&path);

        replace_file(&path, &bin(["AA", "BB", "DE"], false));
        manager.reload_filter("region").expect("what an event does");
        assert_eq!(region_country(&manager).as_deref(), Some("DE"));

        for _ in 0..3 {
            assert!(manager.reload_changed_files().is_empty());
        }
    }

    #[test]
    fn a_file_that_fails_the_trial_lookup_is_not_tried_again_until_it_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        std::fs::write(&path, bin(["AA", "BB", "US"], true)).unwrap();
        let manager = region_manager(&path);

        // A file cut short replaces it. Its header records the size it has,
        // so that it is the trial lookups that fail.
        let whole = bin(["AA", "BB", "DE"], true);
        let half = whole.len() / 2;
        replace_file(&path, &with_header(whole[..half].to_vec(), 1, half));
        assert!(manager.reload_changed_files().is_empty());
        let tried = manager.reload_changed_files();
        assert_eq!(tried.len(), 1, "{tried:?}");
        let message = match &tried[0].1 {
            Ok(()) => panic!("a file cut in half was read"),
            Err(e) => e.to_string(),
        };
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("trial lookup"), "{message}");
        assert_eq!(
            region_country(&manager).as_deref(),
            Some("US"),
            "the database in use stays"
        );

        for _ in 0..3 {
            assert!(
                manager.reload_changed_files().is_empty(),
                "a file that failed is not tried again while it stays as it is"
            );
        }

        // A whole file replaces it: that is a change.
        replace_file(&path, &bin(["AA", "BB", "FR"], true));
        assert!(manager.reload_changed_files().is_empty());
        let tried = manager.reload_changed_files();
        assert_eq!(tried.len(), 1, "{tried:?}");
        assert!(tried[0].1.is_ok(), "{tried:?}");
        assert_eq!(region_country(&manager).as_deref(), Some("FR"));
    }

    #[tokio::test]
    async fn files_that_never_stop_changing_are_read_at_the_limit_of_the_wait() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        std::fs::write(&path, bin(["AA", "BB", "US"], false)).unwrap();
        let manager = region_manager(&path);
        let watcher = Arc::new(GeoDatabaseWatcher::new(Arc::clone(&manager)));
        let events = watcher.start_watching().expect("start watching");
        let sender = watcher.events.read().clone().expect("watching has started");
        let task = tokio::spawn({
            let watcher = Arc::clone(&watcher);
            async move {
                watcher
                    .run(events, Duration::from_millis(20), Duration::from_secs(3600))
                    .await
            }
        });

        // A change is reported again every 5 ms, which is less than `settle`:
        // it never settles. The wait is over 20 times `settle` after it began.
        let reported = tokio::spawn({
            let path = path.clone();
            async move {
                while sender.send(path.clone()).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        });
        replace_file(&path, &bin(["AA", "BB", "DE"], false));
        assert!(
            eventually(|| region_country(&manager).as_deref() == Some("DE")).await,
            "changes that never settled were not read"
        );

        reported.abort();
        task.abort();
    }

    #[tokio::test]
    async fn the_watcher_checks_the_files_on_its_own_when_no_event_comes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.BIN");
        std::fs::write(&path, bin(["AA", "BB", "US"], false)).unwrap();
        let manager = region_manager(&path);
        assert_eq!(region_country(&manager).as_deref(), Some("US"));

        // Nothing is watched, so no event comes.
        let (events, receiver) = mpsc::channel(10);
        let watcher = Arc::new(GeoDatabaseWatcher::new(Arc::clone(&manager)));
        let task = tokio::spawn({
            let watcher = Arc::clone(&watcher);
            async move {
                watcher
                    .run(
                        receiver,
                        Duration::from_millis(50),
                        Duration::from_millis(20),
                    )
                    .await
            }
        });

        replace_file(&path, &bin(["AA", "BB", "DE"], false));
        assert!(
            eventually(|| region_country(&manager).as_deref() == Some("DE")).await,
            "the replaced file was not read by the periodic check"
        );

        drop(events);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the watcher stops when its events end")
            .expect("the watcher does not panic");
    }

    // =========================================================================
    // The databases are read off the runtime
    // =========================================================================

    /// Replace the file at `path` with a FIFO. A FIFO can be opened for
    /// reading only once something opens it for writing: until then, opening
    /// the database waits.
    #[cfg(unix)]
    fn replace_with_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;

        let next = path.with_file_name("next.fifo");
        let name = std::ffi::CString::new(next.as_os_str().as_bytes()).expect("a path without nul");
        // SAFETY: `name` is a nul-terminated path that outlives the call.
        let made = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
        assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());
        std::fs::rename(&next, path).expect("rename over the old file");
    }

    /// The database of the filter `region`, at `path`, made slow to open, and
    /// a check of whether the runtime's other tasks run meanwhile.
    ///
    /// [`Self::start`] puts a FIFO where the database is. Whatever opens the
    /// database then waits, until a thread outside the runtime lets it go:
    /// that thread gives a task of the runtime, started with the FIFO, a few
    /// seconds to say that it ran once the pool had begun to open the FIFO.
    /// What the thread then sends through the FIFO is a database that says
    /// `DE`, so that it shows when the database has been read.
    ///
    /// The thread goes on letting go whatever opens the FIFO until
    /// [`Released::stop`]: a read that comes after the first (the periodic
    /// check can see the FIFO as changed by what was written to it) would
    /// otherwise wait for ever.
    #[cfg(unix)]
    struct SlowOpen {
        /// The task of the runtime
        observer: tokio::task::JoinHandle<()>,
        /// The thread outside the runtime
        guard: std::thread::JoinHandle<bool>,
        /// Set to end the thread
        stop: Arc<std::sync::atomic::AtomicBool>,
    }

    /// A [`SlowOpen`] whose database has been read, and whose FIFO is still
    /// let go.
    #[cfg(unix)]
    struct Released {
        guard: std::thread::JoinHandle<bool>,
        stop: Arc<std::sync::atomic::AtomicBool>,
    }

    #[cfg(unix)]
    impl SlowOpen {
        fn start(manager: &Arc<GeoFilterManager>, path: &Path) -> Self {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            use std::sync::atomic::{AtomicBool, Ordering};

            let pool = pool(manager, "region");
            let database = {
                let next = path.with_file_name("next.mmdb");
                test_database::write_country_database(&next, "DE");
                std::fs::read(&next).expect("read the database")
            };
            replace_with_fifo(path);
            let fifo_stamp = FileStamp::of(path);
            let ran = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));

            // The pool notes the file it is about to open just before it
            // opens it, on the thread that goes on to wait for the FIFO. A
            // task that runs after that, and so after that thread is free,
            // shows that the runtime is not held up by the wait. (The stamp
            // of the FIFO is taken before anything is written to it.) It
            // writes to the map of filters, as a configuration reload does,
            // which must not wait for the read either.
            let observer = tokio::spawn({
                let (ran, manager) = (Arc::clone(&ran), Arc::clone(manager));
                async move {
                    let begun = eventually(|| pool.file.lock().tried == fifo_stamp).await;
                    assert!(begun, "the pool did not begin to open the FIFO");
                    manager.filter_pools.retain(|_, _| true);
                    ran.store(true, Ordering::SeqCst);
                }
            });

            let guard = std::thread::spawn({
                let (stop, fifo) = (Arc::clone(&stop), path.to_path_buf());
                move || {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !ran.load(Ordering::SeqCst) && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    let ran_in_time = ran.load(Ordering::SeqCst);

                    // Let the reader go: open the FIFO for writing, send the
                    // database the first time, close it. Without waiting,
                    // opening it fails until the reader has opened its end.
                    // Some systems do not tell a reader that the writer
                    // closed before it got to read, so this goes on.
                    let give_up = Instant::now() + Duration::from_secs(30);
                    let mut sent = false;
                    while !stop.load(Ordering::SeqCst) && Instant::now() < give_up {
                        let opened = std::fs::OpenOptions::new()
                            .write(true)
                            .custom_flags(libc::O_NONBLOCK)
                            .open(&fifo);
                        if let Ok(mut writer) = opened {
                            sent = sent || writer.write_all(&database).is_ok();
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    ran_in_time
                }
            });

            Self {
                observer,
                guard,
                stop,
            }
        }

        /// Wait until the database that was sent has been read.
        async fn finish(self, manager: &GeoFilterManager) -> Released {
            self.observer.await.expect("the observer task finishes");
            let read = eventually(|| region_country(manager).as_deref() == Some("DE")).await;
            assert!(
                read,
                "the database that was read slowly is not the one in use"
            );
            Released {
                guard: self.guard,
                stop: self.stop,
            }
        }
    }

    #[cfg(unix)]
    impl Released {
        /// Stop letting the FIFO go. Returns whether the task of the runtime
        /// ran while the database was being opened.
        fn stop(self) -> bool {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            self.guard
                .join()
                .expect("the thread outside the runtime finishes")
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_runtime_runs_other_tasks_while_a_changed_database_is_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.mmdb");
        test_database::write_country_database(&path, "US");
        let manager = region_manager(&path);
        assert_eq!(region_country(&manager).as_deref(), Some("US"));

        // Nothing is watched: the one event is sent from here.
        let watcher = Arc::new(GeoDatabaseWatcher::new(Arc::clone(&manager)));
        *watcher.path_to_filters.write() =
            HashMap::from([(path.clone(), vec!["region".to_string()])]);
        let (events, receiver) = mpsc::channel(10);
        let task = tokio::spawn({
            let watcher = Arc::clone(&watcher);
            async move {
                watcher
                    .run(
                        receiver,
                        Duration::from_millis(10),
                        Duration::from_secs(3600),
                    )
                    .await
            }
        });

        let open = SlowOpen::start(&manager, &path);
        events.send(path.clone()).await.expect("the watcher runs");
        let released = open.finish(&manager).await;

        // The FIFO is let go until the watcher has stopped: a read that
        // comes after the first one is let go too.
        drop(events);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the watcher stops when its events end")
            .expect("the watcher does not panic");
        assert!(
            released.stop(),
            "no other task of the runtime ran while the watcher read a changed database"
        );
        assert_eq!(region_country(&manager).as_deref(), Some("DE"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_runtime_runs_other_tasks_while_the_periodic_check_reads_a_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.mmdb");
        test_database::write_country_database(&path, "US");
        let manager = region_manager(&path);
        assert_eq!(region_country(&manager).as_deref(), Some("US"));

        // Nothing is watched, so no event comes.
        let (events, receiver) = mpsc::channel(10);
        let watcher = Arc::new(GeoDatabaseWatcher::new(Arc::clone(&manager)));
        let task = tokio::spawn({
            let watcher = Arc::clone(&watcher);
            async move {
                watcher
                    .run(
                        receiver,
                        Duration::from_millis(50),
                        Duration::from_millis(20),
                    )
                    .await
            }
        });

        // The FIFO is another file than the one the database was opened
        // from. The check reads it once it has stayed as it is for an
        // interval.
        let open = SlowOpen::start(&manager, &path);
        let released = open.finish(&manager).await;

        // The FIFO is let go until the watcher has stopped: the check can
        // see the FIFO as changed by what was written to it, and read it a
        // second time.
        drop(events);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the watcher stops when its events end")
            .expect("the watcher does not panic");
        assert!(
            released.stop(),
            "no other task of the runtime ran while the periodic check read a database"
        );
        assert_eq!(region_country(&manager).as_deref(), Some("DE"));
    }

    #[tokio::test]
    async fn a_read_that_panics_is_reported_as_not_finished() {
        let watcher = GeoDatabaseWatcher::new(Arc::new(GeoFilterManager::new()));

        let panicked = watcher
            .blocking(|_| -> u8 { panic!("a read that fails") })
            .await;
        assert_eq!(panicked, None);
        assert_eq!(watcher.blocking(|_| 1).await, Some(1));
    }
}
