use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Constants & Configuration — портировано из proxy/utils.py + tg_ws_proxy.py
// ---------------------------------------------------------------------------

pub const DEFAULT_PORT: u16 = 1443;
pub const TCP_NODELAY: bool = true;
pub const DEFAULT_RECV_BUF: usize = 256 * 1024;
pub const DEFAULT_SEND_BUF: usize = 256 * 1024;
pub const DEFAULT_POOL_SZ: i32 = 4;

// proxy/tg_ws_proxy.py: IP_FAIL_COOLDOWN / DC_FAIL_COOLDOWN / WS_FAIL_TIMEOUT
// Вместо часа после первого же таймаута (десктоп до 50c980e) —
// растущий cooldown IP: 30 с, удвоение за каждый таймаут подряд, потолок 1 ч.
pub const IP_FAIL_COOLDOWN_INITIAL: f64 = 30.0;
pub const IP_FAIL_COOLDOWN_MAX: f64 = 3600.0;
pub const IP_FAIL_COOLDOWN_MAX_SHIFT: u32 = 7;

// Десктоп 1636903: после плохого handshake не рвать соединение сразу,
// а вычитать до 64 КБ или до 10 с — зонду труднее опознать прокси.
pub const BAD_HANDSHAKE_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
pub const BAD_HANDSHAKE_DRAIN_LIMIT: usize = 64 * 1024;

// OnNetworkChanged — вызовы чаще этого интервала сливаются в один сброс.
pub const NETWORK_CHANGE_DEBOUNCE: f64 = 1.5;
pub const DC_FAIL_COOLDOWN: f64 = 60.0;
pub const WS_FAIL_TIMEOUT: f64 = 2.0;
// Прямой WS-коннект при отсутствии cooldown — 5.0 как в оригинале.
pub const WS_DIRECT_TIMEOUT: f64 = 5.0;

// proxy/utils.py — MTProto handshake layout
pub const HANDSHAKE_LEN: usize = 64;
pub const SKIP_LEN: usize = 8;
pub const PREKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const PROTO_TAG_POS: usize = 56;
pub const DC_IDX_POS: usize = 60;

pub const PROTO_TAG_ABRIDGED: u32 = 0xEFEFEFEF;
pub const PROTO_TAG_INTERMEDIATE: u32 = 0xEEEEEEEE;
pub const PROTO_TAG_SECURE: u32 = 0xDDDDDDDD; // padded intermediate

pub const PROTO_ABRIDGED_INT: u32 = 0xEFEFEFEF;
pub const PROTO_INTERMEDIATE_INT: u32 = 0xEEEEEEEE;
pub const PROTO_PADDED_INTERMEDIATE_INT: u32 = 0xDDDDDDDD;

// proxy/utils.py — зарезервированные префиксы relay_init
pub const RESERVED_FIRST_BYTE: u8 = 0xEF;

pub const BRIDGE_READ_TIMEOUT: Duration = Duration::from_secs(120);
pub const BRIDGE_PING_INTERVAL: Duration = Duration::from_secs(30);
pub const WS_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub const WS_CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
pub const WS_BRIDGE_CHUNK_SIZE: usize = 64 * 1024;
pub const POOLED_FRAME_CAP: usize = WS_BRIDGE_CHUNK_SIZE + 32;

// proxy/pool.py::_WsPool
pub const WS_POOL_REUSE_MAX_AGE: f64 = 120.0;
pub const WS_POOL_CHECK_INTERVAL: f64 = 5.0;
pub const WS_POOL_REFILL_BACKOFF_INITIAL: f64 = 1.0;
pub const WS_POOL_REFILL_BACKOFF_MAX: f64 = 3600.0;
pub const WS_POOL_CONNECT_TIMEOUT: f64 = 8.0;
pub const WS_POOL_FRONTING_TIMEOUT: f64 = 7.0;
pub const FRONTING_SNI: &str = "sprinthost.ru";

// proxy/pool.py::_CfWorkerPool
pub const CF_WORKER_POOL_MAX_AGE: f64 = 100.0;
pub const CF_WORKER_PER_DC_LIMIT: usize = 1;
pub const CF_WORKER_POOL_CHECK_INTERVAL: f64 = 5.0;
pub const CF_WORKER_REFILL_BACKOFF_INITIAL: f64 = 1.0;
pub const CF_WORKER_REFILL_BACKOFF_MAX: f64 = 3600.0;
// Android: ротация пула CF worker останавливается (и пул закрывается), если
// пул этого DC не запрашивали дольше этого времени. Следующий get() запустит
// её снова. На десктопе ротация живёт до остановки прокси.
pub const CF_WORKER_ROTATION_IDLE_STOP: f64 = 300.0;

// Экспонента бэкоффа пулов: delay = initial * 2^min(failures-1, 12).
pub const POOL_BACKOFF_MAX_SHIFT: u32 = 12;

// proxy/bridge.py::_tcp_fallback — бэкофф TCP fallback на (dst, port).
pub const TCP_BACKOFF_INITIAL: f64 = 30.0;
pub const TCP_BACKOFF_MAX: f64 = 3600.0;
pub const TCP_BACKOFF_MAX_SHIFT: u32 = 7;

/// Экспоненциальная задержка: `min(initial * 2^min(failures-1, max_shift), max)`.
/// `failures` считается с 1; 0 трактуется как 1.
pub fn backoff_delay(failures: u32, initial: f64, max: f64, max_shift: u32) -> f64 {
    let shift = failures.saturating_sub(1).min(max_shift);
    (initial * f64::from(1u32 << shift)).min(max)
}

// WS пути — proxy/utils.py
pub const WS_PATH: &str = "/apiws";
pub const WS_PATH_TEST: &str = "/apiws_test";

pub const CFPROXY_CACHE_FILE_NAME: &str = "cfproxy-domains-cache.txt";
pub const CFPROXY_ACTIVE_FILE_NAME: &str = "cfproxy-active-domain.txt";
// Оригинал обновляет пул раз в час (3600с) фоновым потоком.
pub const CFPROXY_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);
pub const CFPROXY_MIN_VALID_DOMAINS: usize = 3;
pub const CFPROXY_DIAL_PHASE_TIMEOUT: Duration = Duration::from_secs(4);
pub const CFPROXY_FALLBACK_PARALLEL: usize = 2;
pub const CFPROXY_429_COOLDOWN: Duration = Duration::from_secs(45);
pub const CFPROXY_429_MAX_COOLDOWN: Duration = Duration::from_secs(300);
pub const CFPROXY_GLOBAL_PARALLEL: usize = 4;

pub static RECV_BUF: AtomicI32 = AtomicI32::new(DEFAULT_RECV_BUF as i32);
pub static SEND_BUF: AtomicI32 = AtomicI32::new(DEFAULT_SEND_BUF as i32);
pub static BUFFER_SIZE: AtomicI32 = AtomicI32::new(256 * 1024);
pub static POOL_SIZE: AtomicI32 = AtomicI32::new(DEFAULT_POOL_SZ);
pub static LOG_VERBOSE: AtomicBool = AtomicBool::new(false);
// proxy/config.py::ProxyConfig — мобильные эквиваленты
// Режим «порт 80» (десктоп --no-secure, 8797796). По умолчанию выключен, как
// на десктопе; приложение передаёт значение явно через SetDisableSecure перед
// каждым StartProxy. Напрямую не читать — только через
// cf_use_tls() и port80_fallback_enabled() ниже.
pub const DISABLE_SECURE_DEFAULT: bool = false;
pub static DISABLE_SECURE: AtomicBool = AtomicBool::new(DISABLE_SECURE_DEFAULT);
// По умолчанию — поведение десктопа; «порт 80» включает только приложение.
const _: () = assert!(!DISABLE_SECURE_DEFAULT);

pub const PORT_TLS: u16 = 443;
pub const PORT_PLAIN: u16 = 80;

/// CF proxy и CF worker: TLS на 443, в режиме «порт 80» — ws:// на 80
/// (как --no-secure на десктопе).
pub fn cf_use_tls() -> bool {
    !DISABLE_SECURE.load(Ordering::Relaxed)
}

/// Прямой WS к DC и TCP fallback: всегда сначала 443. В режиме «порт 80»
/// вторая попытка на 80, если 443 не ответил (таймаут, сброс). Рабочий
/// вариант запоминается на цель (proxy::port_order).
pub fn port80_fallback_enabled() -> bool {
    DISABLE_SECURE.load(Ordering::Relaxed)
}
// Проверка TLS-сертификатов WS (по умолчанию включена). Выключается
// только аварийным рубильником SetTlsVerify(0).
pub static TLS_VERIFY: AtomicBool = AtomicBool::new(true);
pub static FORCE_TEST_DC: AtomicBool = AtomicBool::new(false);
pub static PROXY_PROTOCOL: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct Cfproxy429State {
    pub until: Option<Instant>,
    pub strikes: i32,
}

impl Default for Cfproxy429State {
    fn default() -> Self {
        Cfproxy429State { until: None, strikes: 0 }
    }
}

// Cloudflare proxy config
pub static CFPROXY_ENABLED: AtomicBool = AtomicBool::new(true);

pub struct CfproxyConfig {
    pub user_domain: String,
    pub domains: Vec<String>,
    pub active: String,
    pub cache_dir: String,
}

pub static CFPROXY: Lazy<RwLock<CfproxyConfig>> = Lazy::new(|| {
    RwLock::new(CfproxyConfig {
        user_domain: String::new(),
        domains: Vec::new(),
        active: String::new(),
        cache_dir: String::new(),
    })
});

// proxy/config.py: cfproxy_worker_domains + fake_tls_domain
pub static CF_WORKER_DOMAINS: Lazy<RwLock<Vec<String>>> =
    Lazy::new(|| RwLock::new(Vec::new()));
pub static FAKE_TLS_DOMAIN: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new(String::new()));

pub static CFPROXY_429: Lazy<RwLock<HashMap<String, Cfproxy429State>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub const CFPROXY_DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";

// MTProto proxy secret
pub static PROXY_SECRET: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new("00000000000000000000000000000000".to_string()));

// proxy/config.py::_CFPROXY_ENC — полный список из 20 доменов оригинала.
pub static CFPROXY_ENC: &[&str] = &[
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
    "vwbmtmoi.com",
    "khgrre.com",
    "ulihssf.com",
    "tmhqsdqmfpmk.com",
    "xwuwoqbm.com",
    "orgcnunpj.com",
    "zhkuldz.com",
    "zypoljnslxa.com",
    "efabnxaowuzs.com",
    "zaftuzsftqdq.com",
];

// DC default IPs — proxy/utils.py::DC_DEFAULT_IPS
pub static DC_DEFAULT_IPS: Lazy<HashMap<i32, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(1, "149.154.175.50");
    m.insert(2, "149.154.167.51");
    m.insert(3, "149.154.175.100");
    m.insert(4, "149.154.167.91");
    m.insert(5, "149.154.171.5");
    m.insert(203, "91.105.192.100");
    m
});

// proxy/utils.py::DC_TEST_IPS
pub static DC_TEST_IPS: Lazy<HashMap<i32, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(1, "149.154.175.10");
    m.insert(2, "149.154.167.40");
    m.insert(3, "149.154.175.117");
    m
});

// Telegram protocols & DC mapping
pub fn valid_proto(p: u32) -> bool {
    matches!(p, 0xEFEFEFEF | 0xEEEEEEEE | 0xDDDDDDDD)
}

pub static DC_OVERRIDES: Lazy<HashMap<i32, i32>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(203, 2);
    m
});

// Ключ состояния DC: (dc, is_media, is_test) — аналог строки
// f'{dc}{"t" if is_test else ""}{"m" if is_media else ""}' из оригинала.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DcKey {
    pub dc: i32,
    pub is_media: i32,
    pub is_test: i32,
}

impl DcKey {
    pub fn new(dc: i32, is_media: bool, is_test: bool) -> Self {
        DcKey {
            dc,
            is_media: if is_media { 1 } else { 0 },
            is_test: if is_test { 1 } else { 0 },
        }
    }

    pub fn as_str_key(&self) -> String {
        format!(
            "{}{}{}",
            self.dc,
            if self.is_test != 0 { "t" } else { "" },
            if self.is_media != 0 { "m" } else { "" }
        )
    }
}

// Global state — proxy/tg_ws_proxy.py: ws_blacklist / dc_fail_until / ip_fail_until
pub static DC_OPT: Lazy<RwLock<HashMap<i32, String>>> = Lazy::new(|| RwLock::new(HashMap::new()));
pub static WS_BLACKLIST: Lazy<RwLock<HashMap<DcKey, bool>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
pub static DC_FAIL_UNTIL: Lazy<RwLock<HashMap<DcKey, f64>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
// IP -> (таймаутов подряд, cooldown до). Чистится при успехе WS к этому IP,
// при смене сети (OnNetworkChanged) и в StopProxy.
pub static IP_FAIL_UNTIL: Lazy<RwLock<HashMap<String, (u32, f64)>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Тесты, которые меняют глобальное состояние (POOL_SIZE, CF_WORKER_DOMAINS,
/// IP_FAIL_UNTIL, TCP_BACKOFF и т.п.), идут под этим локом по одному.
#[cfg(test)]
pub(crate) static GLOBAL_STATE_TEST_LOCK: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

pub fn ip_cooldown_active(ip: &str, now: f64) -> bool {
    IP_FAIL_UNTIL
        .read()
        .get(ip)
        .map(|(_, until)| now < *until)
        .unwrap_or(false)
}

/// Таймаут WS к IP: счётчик +1, новый cooldown. Возвращает задержку в секундах.
pub fn ip_cooldown_record_failure(ip: &str, now: f64) -> f64 {
    let mut map = IP_FAIL_UNTIL.write();
    let failures = map.get(ip).map(|(f, _)| *f).unwrap_or(0).saturating_add(1);
    let delay = backoff_delay(
        failures,
        IP_FAIL_COOLDOWN_INITIAL,
        IP_FAIL_COOLDOWN_MAX,
        IP_FAIL_COOLDOWN_MAX_SHIFT,
    );
    map.insert(ip.to_string(), (failures, now + delay));
    delay
}

pub fn ip_cooldown_record_success(ip: &str) {
    if ip.is_empty() {
        return;
    }
    // Не берём write-лок на каждый успешный WS, если записи нет.
    if !IP_FAIL_UNTIL.read().contains_key(ip) {
        return;
    }
    IP_FAIL_UNTIL.write().remove(ip);
}

pub static ZERO64: [u8; 64] = [0u8; 64];

// ---------------------------------------------------------------------------
// Domain validation — proxy/config.py::_is_valid_domain / _normalize_domain_pool
// ---------------------------------------------------------------------------

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|ch| ch.is_alphanumeric() || ch == '-') {
            return false;
        }
    }
    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || !tld.chars().any(|ch| ch.is_alphabetic()) {
        return false;
    }
    true
}

pub fn normalize_domain_pool(domains: &[String]) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for d in domains {
        let item = d.trim().to_lowercase();
        if !is_valid_domain(&item) {
            continue;
        }
        if seen.contains(&item) {
            continue;
        }
        seen.insert(item.clone());
        out.push(item);
    }
    out
}

/// proxy/config.py::coerce_domain_list — строка или список через , ; пробелы.
pub fn coerce_domain_list_str(value: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for item in value.replace(',', " ").replace(';', " ").split_whitespace() {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let key = item.to_lowercase();
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        result.push(item.to_string());
    }
    result
}

// ---------------------------------------------------------------------------
// Reserved relay_init checks — proxy/utils.py
// ---------------------------------------------------------------------------

pub fn is_reserved_start(s: &[u8]) -> bool {
    if s.len() < 4 {
        return false;
    }
    let s4 = &s[..4];
    s4 == b"HEAD"
        || s4 == b"POST"
        || s4 == b"GET "
        || s4 == [0xee, 0xee, 0xee, 0xee]
        || s4 == [0xdd, 0xdd, 0xdd, 0xdd]
        || s4 == [0x16, 0x03, 0x01, 0x02]
        || s4 == b"OPTI"
}

// ---------------------------------------------------------------------------
// Stats — proxy/stats.py
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Stats {
    pub connections_total: AtomicI64,
    pub connections_active: AtomicI64,
    pub connections_ws: AtomicI64,
    pub connections_tcp_fallback: AtomicI64,
    pub connections_cfproxy: AtomicI64,
    pub connections_fronting: AtomicI64,
    pub connections_bad: AtomicI64,
    pub connections_masked: AtomicI64,
    pub connections_http_reject: AtomicI64,
    pub connections_passthrough: AtomicI64,
    pub ws_errors: AtomicI64,
    pub bytes_up: AtomicI64,
    pub bytes_down: AtomicI64,
    pub pool_hits: AtomicI64,
    pub pool_misses: AtomicI64,
    pub cf_pool_hits: AtomicI64,
    pub cf_pool_misses: AtomicI64,
    // Ошибки проверки сертификата / из них — по сроку действия (часы).
    pub tls_verify_errors: AtomicI64,
    pub tls_clock_errors: AtomicI64,
}

pub static STATS: Lazy<Stats> = Lazy::new(Stats::default);

impl Stats {
    pub fn summary(&self) -> String {
        let ph = self.pool_hits.load(Ordering::Relaxed);
        let pm = self.pool_misses.load(Ordering::Relaxed);
        let pool_total = ph + pm;
        let pool_s = if pool_total > 0 {
            format!("{}/{}", ph, pool_total)
        } else {
            "n/a".to_string()
        };
        let cph = self.cf_pool_hits.load(Ordering::Relaxed);
        let cpm = self.cf_pool_misses.load(Ordering::Relaxed);
        let cf_total = cph + cpm;
        let cf_pool_s = if cf_total > 0 {
            format!("{}/{}", cph, cf_total)
        } else {
            "n/a".to_string()
        };
        format!(
            // Новые ключи — только в конец: Kotlin ищет up=/down=/active=
            // через indexOf (ProxyService.extractStat).
            "total={} active={} ws={} tcp_fb={} cf={} front={} bad={} masked={} err={} pool={} cf_pool={} up={} down={} tlserr={} tlsclk={}",
            self.connections_total.load(Ordering::Relaxed),
            self.connections_active.load(Ordering::Relaxed),
            self.connections_ws.load(Ordering::Relaxed),
            self.connections_tcp_fallback.load(Ordering::Relaxed),
            self.connections_cfproxy.load(Ordering::Relaxed),
            self.connections_fronting.load(Ordering::Relaxed),
            self.connections_bad.load(Ordering::Relaxed),
            self.connections_masked.load(Ordering::Relaxed),
            self.ws_errors.load(Ordering::Relaxed),
            pool_s,
            cf_pool_s,
            human_bytes(self.bytes_up.load(Ordering::Relaxed)),
            human_bytes(self.bytes_down.load(Ordering::Relaxed)),
            self.tls_verify_errors.load(Ordering::Relaxed),
            self.tls_clock_errors.load(Ordering::Relaxed),
        )
    }

    pub fn summary_ru(&self) -> String {
        let mut parts = vec![format!("акт:{}", self.connections_active.load(Ordering::Relaxed))];
        let ws = self.connections_ws.load(Ordering::Relaxed);
        if ws > 0 {
            parts.push(format!("ws:{}", ws));
        }
        let cf = self.connections_cfproxy.load(Ordering::Relaxed);
        if cf > 0 {
            parts.push(format!("cf:{}", cf));
        }
        let tcp = self.connections_tcp_fallback.load(Ordering::Relaxed);
        if tcp > 0 {
            parts.push(format!("tcp:{}", tcp));
        }
        let err = self.ws_errors.load(Ordering::Relaxed);
        if err > 0 {
            parts.push(format!("ош:{}", err));
        }
        let tls = self.tls_verify_errors.load(Ordering::Relaxed);
        if tls > 0 {
            parts.push(format!("tls:{}", tls));
        }
        parts.push(format!(
            "↑{} ↓{}",
            human_bytes(self.bytes_up.load(Ordering::Relaxed)),
            human_bytes(self.bytes_down.load(Ordering::Relaxed))
        ));
        parts.join(" | ")
    }

    pub fn reset(&self) {
        self.connections_total.store(0, Ordering::Relaxed);
        self.connections_active.store(0, Ordering::Relaxed);
        self.connections_ws.store(0, Ordering::Relaxed);
        self.connections_tcp_fallback.store(0, Ordering::Relaxed);
        self.connections_cfproxy.store(0, Ordering::Relaxed);
        self.connections_fronting.store(0, Ordering::Relaxed);
        self.connections_bad.store(0, Ordering::Relaxed);
        self.connections_masked.store(0, Ordering::Relaxed);
        self.connections_http_reject.store(0, Ordering::Relaxed);
        self.connections_passthrough.store(0, Ordering::Relaxed);
        self.ws_errors.store(0, Ordering::Relaxed);
        self.bytes_up.store(0, Ordering::Relaxed);
        self.bytes_down.store(0, Ordering::Relaxed);
        self.pool_hits.store(0, Ordering::Relaxed);
        self.pool_misses.store(0, Ordering::Relaxed);
        self.cf_pool_hits.store(0, Ordering::Relaxed);
        self.cf_pool_misses.store(0, Ordering::Relaxed);
        self.tls_verify_errors.store(0, Ordering::Relaxed);
        self.tls_clock_errors.store(0, Ordering::Relaxed);
    }
}

pub fn human_bytes(n: i64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut f = n as f64;
    for (i, u) in units.iter().enumerate() {
        if f.abs() < 1024.0 || i == units.len() - 1 {
            return format!("{:.1}{}", f, u);
        }
        f /= 1024.0;
    }
    format!("{:.1}TB", f)
}

// ---------------------------------------------------------------------------
// Logger (Android log + stderr, 1-в-1 префиксы)
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
fn android_log_line(line: &str) {
    use std::ffi::CString;
    unsafe extern "C" {
        fn __android_log_print(prio: i32, tag: *const i8, fmt: *const i8, ...) -> i32;
    }
    const ANDROID_LOG_INFO: i32 = 4;
    if let (Ok(tag), Ok(fmt), Ok(msg)) =
        (CString::new("TgWsProxy"), CString::new("%s"), CString::new(line))
    {
        unsafe {
            __android_log_print(
                ANDROID_LOG_INFO,
                tag.as_ptr() as *const i8,
                fmt.as_ptr() as *const i8,
                msg.as_ptr() as *const i8,
            );
        }
    }
}

#[cfg(not(target_os = "android"))]
fn android_log_line(_line: &str) {}

// Цензура доменов в логах — аналог DomainCensorFilter из proxy/utils.py:
// telegram.org и *.telegram.org не маскируем, остальное частично маскируем.
fn censor_domains(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let bytes = msg.as_bytes();
    let mut i = 0;
    while i < msg.len() {
        let start = i;
        while i < msg.len()
            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b'.')
        {
            i += 1;
        }
        if start == i {
            let ch = msg[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let token = &msg[start..i];
        if token.contains('.') && token.len() > 4 && is_likely_domain(token) {
            let lower = token.to_lowercase();
            let trimmed = lower.trim_end_matches('.');
            if trimmed == "telegram.org"
                || trimmed.ends_with(".telegram.org")
                || trimmed.ends_with(".log")
            {
                out.push_str(token);
            } else {
                out.push_str(&mask_domain(token));
            }
        } else {
            out.push_str(token);
        }
    }
    out
}

fn is_likely_domain(token: &str) -> bool {
    let t = token.trim_end_matches('.');
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let tld = parts[parts.len() - 1];
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 63
            && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn mask_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return domain.to_string();
    }
    parts
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            if idx == parts.len() - 1 {
                p.to_string()
            } else {
                let keep = p.len() / 2;
                format!("{}{}", &p[..keep], "*".repeat(p.len() - keep))
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn emit(prefix: &str, msg: &str) {
    let line = format!("{}{}", prefix, censor_domains(msg));
    eprintln!("{}", line);
    android_log_line(&line);
}

pub fn log_info(msg: &str) {
    emit("", msg);
}
pub fn log_warn(msg: &str) {
    emit("[WARN] ", msg);
}
pub fn log_error(msg: &str) {
    emit("[ERROR] ", msg);
}
pub fn log_debug(msg: &str) {
    if LOG_VERBOSE.load(Ordering::Relaxed) {
        emit("[DEBUG] ", msg);
    }
}

#[macro_export]
macro_rules! linfo  { ($($a:tt)*) => { $crate::config::log_info(&format!($($a)*)) }; }
#[macro_export]
macro_rules! lwarn  { ($($a:tt)*) => { $crate::config::log_warn(&format!($($a)*)) }; }
#[macro_export]
macro_rules! lerror { ($($a:tt)*) => { $crate::config::log_error(&format!($($a)*)) }; }
#[macro_export]
macro_rules! ldebug { ($($a:tt)*) => { $crate::config::log_debug(&format!($($a)*)) }; }

pub fn init_logging(verbose: bool) {
    LOG_VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn now_unix_f64() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn now_monotonic() -> f64 {
    use std::time::Instant;
    static START: Lazy<Instant> = Lazy::new(Instant::now);
    START.elapsed().as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_starts_cover_all_desktop_prefixes() {
        // proxy/utils.py::RESERVED_STARTS (с OPTI из c317406).
        let reserved: [&[u8; 4]; 7] = [
            b"HEAD",
            b"POST",
            b"GET ",
            &[0xee, 0xee, 0xee, 0xee],
            &[0xdd, 0xdd, 0xdd, 0xdd],
            &[0x16, 0x03, 0x01, 0x02],
            b"OPTI",
        ];
        for prefix in reserved {
            let mut init = [0x42u8; 64];
            init[..4].copy_from_slice(prefix);
            assert!(is_reserved_start(&init[..4]), "{:?}", prefix);
            assert!(is_reserved_start(&init), "{:?} (полный relay_init)", prefix);
        }
    }

    #[test]
    fn reserved_starts_reject_other_prefixes_and_short_input() {
        for prefix in [b"OPTX", b"OPT\x00", b"GETX", b"opti", b"\x16\x03\x01\x03"] {
            assert!(!is_reserved_start(prefix), "{:?}", prefix);
        }
        assert!(!is_reserved_start(b"OPT"));
        assert!(!is_reserved_start(b""));
    }

    #[test]
    fn backoff_delay_is_capped_exponential() {
        let pool: Vec<f64> = (1..=15)
            .map(|f| backoff_delay(f, 1.0, 3600.0, POOL_BACKOFF_MAX_SHIFT))
            .collect();
        assert_eq!(&pool[..4], &[1.0, 2.0, 4.0, 8.0]);
        assert_eq!(pool[12], 3600.0); // 2^12 = 4096 -> потолок 3600
        assert_eq!(pool[14], 3600.0);

        let tcp: Vec<f64> = (1..=10)
            .map(|f| backoff_delay(f, TCP_BACKOFF_INITIAL, TCP_BACKOFF_MAX, TCP_BACKOFF_MAX_SHIFT))
            .collect();
        assert_eq!(&tcp[..7], &[30.0, 60.0, 120.0, 240.0, 480.0, 960.0, 1920.0]);
        assert_eq!(tcp[7], 3600.0); // 30 * 2^7 = 3840 -> потолок
        assert_eq!(tcp[9], 3600.0);

        assert_eq!(backoff_delay(0, 1.0, 2.0, 12), 1.0);
        assert_eq!(backoff_delay(u32::MAX, 1.0, 2.0, 12), 2.0);
    }

    #[test]
    fn ip_cooldown_grows_from_30s_to_hour_and_success_clears() {
        let _lock = GLOBAL_STATE_TEST_LOCK.blocking_lock();
        let ip = "198.51.100.77";
        IP_FAIL_UNTIL.write().remove(ip);
        let now = 1000.0;
        assert!(!ip_cooldown_active(ip, now));
        let delays: Vec<f64> = (0..9).map(|_| ip_cooldown_record_failure(ip, now)).collect();
        assert_eq!(delays, [30.0, 60.0, 120.0, 240.0, 480.0, 960.0, 1920.0, 3600.0, 3600.0]);
        assert!(ip_cooldown_active(ip, now + 3599.0));
        assert!(!ip_cooldown_active(ip, now + 3600.0));

        ip_cooldown_record_success(ip);
        assert!(!ip_cooldown_active(ip, now));
        assert_eq!(ip_cooldown_record_failure(ip, now), 30.0);
        IP_FAIL_UNTIL.write().remove(ip);
    }

    #[test]
    fn ip_cooldown_success_for_unknown_or_empty_ip_is_noop() {
        let _lock = GLOBAL_STATE_TEST_LOCK.blocking_lock();
        ip_cooldown_record_success("");
        ip_cooldown_record_success("198.51.100.78");
        assert!(!IP_FAIL_UNTIL.read().contains_key("198.51.100.78"));
    }

    /// Повтор ProxyService.extractStat из Kotlin: indexOf(key) до пробела.
    fn kotlin_extract_stat<'a>(stats: &'a str, key: &str) -> &'a str {
        match stats.find(key) {
            None => "0B",
            Some(i) => {
                let rest = &stats[i + key.len()..];
                rest.split(' ').next().unwrap_or("")
            }
        }
    }

    #[test]
    fn stats_summary_appends_tls_counters_without_breaking_kotlin_parsing() {
        let st = Stats::default();
        st.connections_active.store(3, Ordering::Relaxed);
        st.bytes_up.store(2048, Ordering::Relaxed);
        st.bytes_down.store(1024 * 1024, Ordering::Relaxed);
        st.tls_verify_errors.store(5, Ordering::Relaxed);
        st.tls_clock_errors.store(2, Ordering::Relaxed);
        let s = st.summary();
        assert!(s.ends_with(" up=2.0KB down=1.0MB tlserr=5 tlsclk=2"), "{}", s);
        assert_eq!(kotlin_extract_stat(&s, "up="), "2.0KB");
        assert_eq!(kotlin_extract_stat(&s, "down="), "1.0MB");
        assert_eq!(kotlin_extract_stat(&s, "active="), "3");
        st.reset();
        assert!(st.summary().ends_with("tlserr=0 tlsclk=0"));
    }
}
