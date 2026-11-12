// ---------------------------------------------------------------------------
// Проверка TLS-сертификатов — порт create_ssl_context() из proxy/utils.py
// (десктоп e519c4d, caa949b).
//
// Десктоп держит два контекста: обычный проверяет цепочку и имя хоста,
// контекст для fronting (чужой SNI) проверяет цепочку, но не имя. Здесь то же:
//   * TLS_VERIFIED — корни Mozilla из webpki-roots (аналог certifi), цепочка,
//     срок действия и имя;
//   * TLS_FRONTING — та же проверка, но несовпадение имени не считается
//     ошибкой (FrontingVerifier);
//   * TLS_INSECURE — без проверки (NoVerify), только при SetTlsVerify(0).
//
// Инвариант по ClientHello (десктоп a70fc8c оставил только X25519, чтобы
// убрать длинный гибридный ML-KEM): провайдер здесь ring, в нём ML-KEM нет,
// ClientHello и так короткий. При переходе на aws-lc-rs нужно явно ограничить
// kx_groups, иначе ClientHello вырастет.
// ---------------------------------------------------------------------------

use crate::config::*;
use crate::{linfo, lwarn};
use once_cell::sync::Lazy;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::time_provider::{DefaultTimeProvider, TimeProvider};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const SESSION_CACHE_SIZE: usize = 100;

/// Нижняя граница правдоподобного системного времени: дата добавления проверки сертификатов
/// (2026-11-12T00:00:00Z). Если часы показывают раньше, они точно неверны,
/// и все проверки срока сертификатов будут падать. Константа, а не время
/// сборки из build.rs, чтобы .so собиралась воспроизводимо.
pub const CLOCK_FLOOR_UNIX: u64 = 1_794_441_600;

/// Предупреждения одной категории — не чаще раза в минуту.
const WARN_INTERVAL: Duration = Duration::from_secs(60);

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// ---------------------------------------------------------------------------
// Верификаторы
// ---------------------------------------------------------------------------

/// Fronting: цепочка, срок и подписи проверяются как обычно, принимается
/// только несовпадение имени (check_hostname=False в десктопе). webpki
/// сверяет имя после проверки цепочки, поэтому NotValidForName означает,
/// что сама цепочка валидна.
#[derive(Debug)]
struct FrontingVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for FrontingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Без проверки сертификатов. Только при SetTlsVerify(0).
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ---------------------------------------------------------------------------
// Конфиги
// ---------------------------------------------------------------------------

pub(crate) struct TlsConfigs {
    pub verified: Arc<ClientConfig>,
    pub fronting: Arc<ClientConfig>,
}

fn finish(mut cfg: ClientConfig) -> Arc<ClientConfig> {
    // Кеш сессий, как tls.NewLRUClientSessionCache(100) в Go-версии.
    cfg.resumption = rustls::client::Resumption::in_memory_sessions(SESSION_CACHE_SIZE);
    Arc::new(cfg)
}

/// Конфиги с проверкой для заданных корней и источника времени
/// (в тестах — свои корни и «неверные часы»).
pub(crate) fn build_verified_configs(
    roots: Arc<RootCertStore>,
    time: Arc<dyn TimeProvider>,
) -> TlsConfigs {
    let provider = ring_provider();
    let verified = ClientConfig::builder_with_details(provider.clone(), time.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports default TLS versions")
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let inner = WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .expect("non-empty root store");
    let fronting = ClientConfig::builder_with_details(provider, time)
        .with_safe_default_protocol_versions()
        .expect("ring supports default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FrontingVerifier { inner }))
        .with_no_client_auth();
    TlsConfigs {
        verified: finish(verified),
        fronting: finish(fronting),
    }
}

fn mozilla_roots() -> Arc<RootCertStore> {
    Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    })
}

static TLS_VERIFIED: Lazy<TlsConfigs> =
    Lazy::new(|| build_verified_configs(mozilla_roots(), Arc::new(DefaultTimeProvider)));

static TLS_INSECURE: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
    finish(
        ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .expect("ring supports default TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    )
});

/// Конфиг для исходящего TLS-соединения WS.
pub fn client_config(fronting: bool) -> Arc<ClientConfig> {
    if !TLS_VERIFY.load(Ordering::Relaxed) {
        return TLS_INSECURE.clone();
    }
    if fronting {
        TLS_VERIFIED.fronting.clone()
    } else {
        TLS_VERIFIED.verified.clone()
    }
}

// ---------------------------------------------------------------------------
// Классификация и логирование ошибок проверки
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFailure {
    /// Срок действия: почти всегда неверные часы на устройстве.
    Clock = 0,
    /// Неизвестный издатель: перехват HTTPS или устаревшие корни.
    UnknownIssuer = 1,
    /// Сертификат не для этого имени (вне fronting).
    NameMismatch = 2,
    /// Прочие ошибки сертификата.
    Other = 3,
}

pub fn classify(err: &rustls::Error) -> Option<TlsFailure> {
    let rustls::Error::InvalidCertificate(ce) = err else {
        return None;
    };
    Some(match ce {
        CertificateError::Expired
        | CertificateError::ExpiredContext { .. }
        | CertificateError::NotValidYet
        | CertificateError::NotValidYetContext { .. } => TlsFailure::Clock,
        CertificateError::UnknownIssuer => TlsFailure::UnknownIssuer,
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            TlsFailure::NameMismatch
        }
        _ => TlsFailure::Other,
    })
}

/// rustls::Error внутри io::Error, которую возвращает TlsConnector::connect.
pub fn tls_error_of(e: &std::io::Error) -> Option<&rustls::Error> {
    e.get_ref()?.downcast_ref::<rustls::Error>()
}

static LAST_WARN: Lazy<parking_lot::Mutex<[Option<Instant>; 4]>> =
    Lazy::new(|| parking_lot::Mutex::new([None; 4]));

fn should_warn(kind: TlsFailure, now: Instant) -> bool {
    let mut last = LAST_WARN.lock();
    let slot = &mut last[kind as usize];
    match slot {
        Some(t) if now.duration_since(*t) < WARN_INTERVAL => false,
        _ => {
            *slot = Some(now);
            true
        }
    }
}

/// Учитывает ошибку TLS-хендшейка: счётчики и предупреждение в лог (не чаще
/// раза в минуту на категорию). Возвращает категорию, если это ошибка
/// проверки сертификата.
pub fn report_handshake_error(e: &std::io::Error, domain: &str, dial: &str) -> Option<TlsFailure> {
    let err = tls_error_of(e)?;
    let kind = classify(err)?;
    STATS.tls_verify_errors.fetch_add(1, Ordering::Relaxed);
    if kind == TlsFailure::Clock {
        STATS.tls_clock_errors.fetch_add(1, Ordering::Relaxed);
    }
    if !should_warn(kind, Instant::now()) {
        return Some(kind);
    }
    match kind {
        TlsFailure::Clock => lwarn!(
            "TLS: сертификат {} (через {}) не прошёл проверку срока действия ({}). \
             Проверьте дату и время на устройстве",
            domain, dial, err
        ),
        TlsFailure::UnknownIssuer => lwarn!(
            "TLS: сертификат {} (через {}) выдан неизвестным центром сертификации. \
             Возможен перехват HTTPS (антивирус, корпоративный прокси, фильтр трафика)",
            domain, dial
        ),
        TlsFailure::NameMismatch => lwarn!(
            "TLS: сертификат на {} не подходит для имени {} ({})",
            dial, domain, err
        ),
        TlsFailure::Other => lwarn!(
            "TLS: сертификат {} (через {}) отклонён: {}",
            domain, dial, err
        ),
    }
    Some(kind)
}

// ---------------------------------------------------------------------------
// Проверка часов при старте
// ---------------------------------------------------------------------------

pub fn clock_is_implausible(now_unix: u64) -> bool {
    now_unix < CLOCK_FLOOR_UNIX
}

/// YYYY-MM-DD по unix-времени (UTC), без зависимостей.
pub fn format_utc_date(unix: u64) -> String {
    // Алгоритм days_from_civil наоборот (H. Hinnant).
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Вызывается в StartProxy: одно предупреждение сразу при запуске, до первых
/// ошибок соединений.
pub fn log_startup_tls_state() {
    if !TLS_VERIFY.load(Ordering::Relaxed) {
        lwarn!("TLS: проверка сертификатов выключена (SetTlsVerify(0))");
        return;
    }
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if clock_is_implausible(now) {
        lwarn!(
            "Системное время {} раньше даты сборки прокси ({}): часы устройства неверны, \
             TLS-соединения будут отклоняться. Включите автоматическую установку даты и времени",
            format_utc_date(now),
            format_utc_date(CLOCK_FLOOR_UNIX)
        );
    } else {
        linfo!("TLS: проверка сертификатов включена");
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::PrivateKeyDer;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    // Тестовый УЦ и сертификат на test.example (P-256, срок до 2126 года,
    // notBefore 2026-11-12). Ключ только для тестов, см. testdata/tls/README.
    const CA_DER: &[u8] = include_bytes!("testdata/tls/ca.der");
    const LEAF_DER: &[u8] = include_bytes!("testdata/tls/leaf.der");
    const LEAF_KEY_DER: &[u8] = include_bytes!("testdata/tls/leaf.key.der");

    #[derive(Debug)]
    struct FixedTime(u64);

    impl TimeProvider for FixedTime {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
        }
    }

    const Y2030: u64 = 1_893_456_000; // внутри срока сертификата
    const Y2020: u64 = 1_577_836_800; // до notBefore: «часы отстают»
    const Y2200: u64 = 7_258_118_400; // после notAfter: «часы спешат»

    fn test_roots() -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(CA_DER.to_vec())).unwrap();
        Arc::new(roots)
    }

    fn configs(roots: Arc<RootCertStore>, now: u64) -> TlsConfigs {
        build_verified_configs(roots, Arc::new(FixedTime(now)))
    }

    /// Локальный TLS-сервер с сертификатом test.example. Принимает одно
    /// соединение и отвечает "ok".
    async fn server() -> std::net::SocketAddr {
        let cfg = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(LEAF_DER.to_vec())],
                PrivateKeyDer::try_from(LEAF_KEY_DER.to_vec()).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let _ = tls.write_all(b"ok").await;
                let _ = tls.shutdown().await;
            }
        });
        addr
    }

    async fn connect(cfg: Arc<ClientConfig>, name: &str) -> std::io::Result<()> {
        let addr = server().await;
        let tcp = TcpStream::connect(addr).await?;
        let sn = ServerName::try_from(name.to_string()).unwrap();
        tokio_rustls::TlsConnector::from(cfg).connect(sn, tcp).await.map(|_| ())
    }

    fn kind(r: std::io::Result<()>) -> Option<TlsFailure> {
        let e = r.expect_err("handshake must fail");
        classify(tls_error_of(&e).expect("rustls error inside io::Error"))
    }

    #[tokio::test]
    async fn valid_chain_and_name_pass() {
        let c = configs(test_roots(), Y2030);
        connect(c.verified, "test.example").await.unwrap();
        connect(c.fronting, "test.example").await.unwrap();
    }

    #[tokio::test]
    async fn wrong_name_fails_normally_but_passes_for_fronting() {
        let c = configs(test_roots(), Y2030);
        assert_eq!(kind(connect(c.verified, "sprinthost.ru").await), Some(TlsFailure::NameMismatch));
        connect(c.fronting, "sprinthost.ru").await.unwrap();
    }

    #[tokio::test]
    async fn unknown_issuer_fails_in_both_modes() {
        // Корни Mozilla тестовый УЦ не знают: как при перехвате HTTPS.
        let c = configs(mozilla_roots(), Y2030);
        assert_eq!(kind(connect(c.verified, "test.example").await), Some(TlsFailure::UnknownIssuer));
        assert_eq!(kind(connect(c.fronting, "sprinthost.ru").await), Some(TlsFailure::UnknownIssuer));
    }

    #[tokio::test]
    async fn wrong_clock_is_classified_as_clock_error_in_both_modes() {
        for now in [Y2020, Y2200] {
            let c = configs(test_roots(), now);
            assert_eq!(kind(connect(c.verified, "test.example").await), Some(TlsFailure::Clock));
            // Fronting прощает только имя, но не срок.
            assert_eq!(kind(connect(c.fronting, "sprinthost.ru").await), Some(TlsFailure::Clock));
        }
    }

    #[tokio::test]
    async fn kill_switch_accepts_anything() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        TLS_VERIFY.store(false, Ordering::SeqCst);
        let r = connect(client_config(false), "sprinthost.ru").await;
        TLS_VERIFY.store(true, Ordering::SeqCst);
        r.unwrap();
        // С включённой проверкой реальные корни тестовый сервер отвергают.
        assert_eq!(
            kind(connect(client_config(false), "test.example").await),
            Some(TlsFailure::UnknownIssuer)
        );
    }

    #[tokio::test]
    async fn report_counts_errors_and_rate_limits_warnings() {
        let c = configs(test_roots(), Y2200);
        let e = connect(c.verified, "test.example").await.unwrap_err();
        let verify0 = STATS.tls_verify_errors.load(Ordering::SeqCst);
        let clock0 = STATS.tls_clock_errors.load(Ordering::SeqCst);
        assert_eq!(report_handshake_error(&e, "test.example", "127.0.0.1"), Some(TlsFailure::Clock));
        assert_eq!(report_handshake_error(&e, "test.example", "127.0.0.1"), Some(TlsFailure::Clock));
        assert!(STATS.tls_verify_errors.load(Ordering::SeqCst) >= verify0 + 2);
        assert!(STATS.tls_clock_errors.load(Ordering::SeqCst) >= clock0 + 2);

        // Не-TLS ошибка не считается.
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert_eq!(report_handshake_error(&io, "x", "y"), None);
    }

    #[test]
    fn warnings_are_limited_to_one_per_minute_per_category() {
        let t0 = Instant::now();
        // Категория Other в других тестах не встречается.
        LAST_WARN.lock()[TlsFailure::Other as usize] = None;
        assert!(should_warn(TlsFailure::Other, t0));
        assert!(!should_warn(TlsFailure::Other, t0 + Duration::from_secs(59)));
        assert!(should_warn(TlsFailure::Other, t0 + Duration::from_secs(60)));
    }

    #[test]
    fn clock_floor_and_date_format() {
        assert_eq!(format_utc_date(CLOCK_FLOOR_UNIX), "2026-11-12");
        assert_eq!(format_utc_date(0), "1970-01-01");
        assert_eq!(format_utc_date(951_782_400), "2000-02-29");
        assert!(clock_is_implausible(Y2020));
        assert!(clock_is_implausible(0));
        assert!(!clock_is_implausible(CLOCK_FLOOR_UNIX));
        assert!(!clock_is_implausible(Y2030));
    }

    #[test]
    fn mozilla_roots_are_bundled() {
        assert!(webpki_roots::TLS_SERVER_ROOTS.len() > 100);
    }
}
