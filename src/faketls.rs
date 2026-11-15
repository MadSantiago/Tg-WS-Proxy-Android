//! Fake TLS (ee-secret), порт десктопного `proxy/fake_tls.py` v1.11.3+:
//! 7fb01a7 (#1473) и 44c5ee2: ServerHello строится по ClientHello
//! (cipher suite, key_share, зеркалирование X25519MLKEM768), размер первой
//! ApplicationData-записи берётся из профиля маскирующего сайта (без профиля —
//! 64–160 байт вместо 1900–2100), задержка ответа 8–24 мс;
//! dbc8b78 (#1532): кеш client_random, повторённый ClientHello уходит на
//! маскирующий сайт.

use crate::config::{log_debug, log_info, log_warn, STATS};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use sha2::Sha256;
use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

const CLIENT_RANDOM_OFFSET: usize = 11;
const CLIENT_RANDOM_LEN: usize = 32;
const SESSION_ID_OFFSET: usize = 44;
const SESSION_ID_LEN: usize = 32;

const TIMESTAMP_TOLERANCE: i64 = 120;
const TLS_APPDATA_MAX: usize = 16384;

const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519MLKEM768: u16 = 0x11ec;

const X25519_KEY_LEN: usize = 32;
const X25519MLKEM768_CLIENT_SHARE_LEN: usize = 1216;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

/// TLS 1.3 suites в том порядке, в каком их выбирает типичный сервер.
const CIPHER_PREFERENCE: [u16; 3] = [0x1301, 0x1303, 0x1302];

/// Границы единственной ApplicationData-записи после CCS: нижняя — самая
/// короткая запись telemt, верхняя — предел TLS.
const APPDATA_MIN: usize = 64;
/// Без профиля сайта — около 64 байт, как у telemt, который проходит DPI,
/// и далеко от 1900–2100 байт классического ответа MTProxy.
const FALLBACK_APPDATA_RANGE: (usize, usize) = (64, 160);

const SERVER_HELLO_DELAY_MS: (u64, u64) = (8, 24);

const PROFILE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Hello проходит проверку времени TIMESTAMP_TOLERANCE в обе стороны плюс
/// секунду из-за усечения часов; столько и помним его random.
const REPLAY_WINDOW: Duration = Duration::from_secs(2 * TIMESTAMP_TOLERANCE as u64 + 1);
/// На десктопе 65 536. В кеш попадают только hello, прошедшие HMAC с
/// секретом, поэтому лимит — это число настоящих рукопожатий за ~4 минуты;
/// для телефона 8 192 с запасом (≈ 400 КБ в худшем случае).
const REPLAY_CACHE_SIZE: usize = 8192;

const READ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_RECORD_TIMEOUT: Duration = Duration::from_secs(10);
const MASKING_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

const SH_RANDOM_OFF: usize = 11;

type HmacSha256 = Hmac<Sha256>;

pub struct FakeTlsStream {
    pub read: Box<dyn AsyncRead + Send + Unpin>,
    pub write: Box<dyn AsyncWrite + Send + Unpin>,
}

// ---------------------------------------------------------------------------
// Кеш повторов (dbc8b78)
// ---------------------------------------------------------------------------

/// client_random принятых ClientHello; повтор — это replay-зонд. Один кеш на
/// процесс, как на десктопе: он переживает перезапуск прокси.
struct ReplayCache {
    window: Duration,
    size: usize,
    order: VecDeque<([u8; 32], Instant)>,
    seen: HashSet<[u8; 32]>,
}

impl ReplayCache {
    fn new(window: Duration, size: usize) -> Self {
        ReplayCache {
            window,
            size,
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    fn first_seen(&mut self, client_random: &[u8; 32], now: Instant) -> bool {
        // Порядок вставки совпадает с порядком истечения.
        while let Some((key, expiry)) = self.order.front() {
            if *expiry > now {
                break;
            }
            self.seen.remove(key);
            self.order.pop_front();
        }
        if self.seen.contains(client_random) {
            return false;
        }
        if self.order.len() >= self.size {
            if let Some((key, _)) = self.order.pop_front() {
                self.seen.remove(&key);
            }
        }
        self.order.push_back((*client_random, now + self.window));
        self.seen.insert(*client_random);
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.order.len()
    }
}

static REPLAY_CACHE: Lazy<Mutex<ReplayCache>> =
    Lazy::new(|| Mutex::new(ReplayCache::new(REPLAY_WINDOW, REPLAY_CACHE_SIZE)));

// ---------------------------------------------------------------------------
// Профиль маскирующего сайта (7fb01a7)
// ---------------------------------------------------------------------------

/// Длина первой зашифрованной записи сайта после ServerHello; 0 — профиля нет.
static PROFILED_APPDATA_LEN: AtomicUsize = AtomicUsize::new(0);
static PROBE_GEN: AtomicU64 = AtomicU64::new(0);

fn clamp_profile(length: Option<usize>) -> usize {
    match length {
        None => 0,
        Some(n) => n.clamp(APPDATA_MIN, TLS_APPDATA_MAX),
    }
}

pub fn set_profiled_appdata_len(length: Option<usize>) {
    PROFILED_APPDATA_LEN.store(clamp_profile(length), Ordering::Relaxed);
}

pub fn profiled_appdata_len() -> Option<usize> {
    match PROFILED_APPDATA_LEN.load(Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

fn fallback_appdata_len() -> usize {
    rand::thread_rng().gen_range(FALLBACK_APPDATA_RANGE.0..=FALLBACK_APPDATA_RANGE.1)
}

fn appdata_len() -> usize {
    profiled_appdata_len().unwrap_or_else(fallback_appdata_len)
}

/// Длина первой ApplicationData-записи в первом ответе сервера.
/// `None` — нужно больше данных, `Some(0)` — её там не будет (alert,
/// рукопожатие TLS 1.2, мусор).
pub fn first_appdata_record_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    while pos + 5 <= data.len() {
        let rtype = data[pos];
        let rec_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        if rtype == TLS_RECORD_APPDATA {
            return Some(rec_len);
        }
        if rtype != TLS_RECORD_HANDSHAKE && rtype != TLS_RECORD_CCS {
            return Some(0);
        }
        pos += 5 + rec_len;
    }
    None
}

/// ClientHello TLS 1.3 (ALPN h2/http1.1) от rustls; рукопожатие не
/// завершается, нужен только первый полёт сервера.
fn probe_client_hello(domain: &str) -> Option<Vec<u8>> {
    let name = rustls_pki_types::ServerName::try_from(domain.to_string()).ok()?;
    let mut conn = rustls::ClientConnection::new(crate::tls::probe_client_config(), name).ok()?;
    let mut out = Vec::with_capacity(512);
    while conn.wants_write() {
        if conn.write_tls(&mut out).ok()? == 0 {
            break;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Замер первой зашифрованной записи маскирующего сайта. Один общий срок на
/// соединение, отправку и чтение, как на десктопе.
pub async fn probe_appdata_len(domain: &str, port: u16, timeout: Duration) -> Option<usize> {
    let Some(hello) = probe_client_hello(domain) else {
        log_warn(&format!("Fake TLS profile: cannot build ClientHello for {}", domain));
        return None;
    };
    let probe = async {
        let mut s = TcpStream::connect((domain, port)).await?;
        s.write_all(&hello).await?;
        let mut flight = Vec::with_capacity(8192);
        let mut buf = [0u8; 16384];
        loop {
            let n = s.read(&mut buf).await?;
            if n == 0 {
                return Ok::<Option<usize>, std::io::Error>(None);
            }
            flight.extend_from_slice(&buf[..n]);
            if let Some(len) = first_appdata_record_len(&flight) {
                return Ok(if len == 0 { None } else { Some(len) });
            }
        }
    };
    match tokio::time::timeout(timeout, probe).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            log_warn(&format!("Fake TLS profile: cannot probe {}:{}: {}", domain, port, e));
            None
        }
        Err(_) => {
            log_warn(&format!("Fake TLS profile: cannot probe {}:{}: timeout", domain, port));
            None
        }
    }
}

/// Замер профиля в фоне. На десктопе он идёт до открытия порта; на телефоне
/// старт не ждёт сеть: до результата ServerHello использует случайный размер.
/// `only_if_missing` — повтор после смены сети, если первый замер не удался.
/// Каждый вызов начинает новое поколение: результат старого замера (прошлый
/// запуск прокси, прошлая сеть) отбрасывается.
pub fn spawn_profile_probe(domain: String, cancel: CancellationToken, only_if_missing: bool) {
    if domain.is_empty() || (only_if_missing && profiled_appdata_len().is_some()) {
        return;
    }
    let gen = PROBE_GEN.fetch_add(1, Ordering::AcqRel) + 1;
    tokio::spawn(async move {
        let res = tokio::select! {
            _ = cancel.cancelled() => return,
            r = probe_appdata_len(&domain, 443, PROFILE_PROBE_TIMEOUT) => r,
        };
        if PROBE_GEN.load(Ordering::Acquire) != gen {
            return;
        }
        set_profiled_appdata_len(res);
        match profiled_appdata_len() {
            Some(n) => log_info(&format!("Fake TLS profile: first encrypted record {} bytes", n)),
            None => log_warn("Fake TLS profile unavailable, ServerHello uses random record sizes"),
        }
    });
}

/// Новый запуск прокси: профиль прошлого домена недействителен.
pub fn reset_profile() {
    PROBE_GEN.fetch_add(1, Ordering::AcqRel);
    set_profiled_appdata_len(None);
}

// ---------------------------------------------------------------------------
// ClientHello / ServerHello
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
struct ClientHelloInfo {
    cipher_suites: Vec<u16>,
    /// named group -> длина key_exchange (первое вхождение).
    key_shares: Vec<(u16, usize)>,
}

impl ClientHelloInfo {
    fn key_share_len(&self, group: u16) -> Option<usize> {
        self.key_shares.iter().find(|(g, _)| *g == group).map(|(_, l)| *l)
    }
}

fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<([u8; 32], [u8; 32], i64)> {
    if data.len() < 43 {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random
        .copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    for b in &mut zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] {
        *b = 0;
    }

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    // Сравнение без раннего выхода, как hmac.compare_digest.
    let diff = expected[..28]
        .iter()
        .zip(&client_random[..28])
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return None;
    }

    let mut ts_bytes = [0u8; 4];
    for i in 0..4 {
        ts_bytes[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_bytes) as i64;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - timestamp).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; 32];
    if data.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id
            .copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }

    Some((client_random, session_id, timestamp))
}

fn be16(data: &[u8], pos: usize) -> Option<usize> {
    let b = data.get(pos..pos + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]) as usize)
}

/// Предлагаемые cipher suites и группы key_share. На битом вводе — пустой
/// результат, тогда ответ строится как X25519 / TLS_AES_128_GCM_SHA256.
fn parse_client_hello(data: &[u8]) -> ClientHelloInfo {
    fn inner(data: &[u8]) -> Option<ClientHelloInfo> {
        let mut pos = 5 + 4 + 2 + CLIENT_RANDOM_LEN;
        pos += 1 + *data.get(pos)? as usize;

        let suites_len = be16(data, pos)?;
        pos += 2;
        let suites_end = pos + suites_len;
        if suites_end > data.len() {
            return None;
        }
        let mut suites = Vec::with_capacity(suites_len / 2);
        let mut off = pos;
        while off + 1 < suites_end {
            suites.push(be16(data, off)? as u16);
            off += 2;
        }
        pos = suites_end;

        pos += 1 + *data.get(pos)? as usize;

        let ext_total = be16(data, pos)?;
        pos += 2;
        let ext_end = (pos + ext_total).min(data.len());
        let mut key_shares: Vec<(u16, usize)> = Vec::new();
        while pos + 4 <= ext_end {
            let ext_type = be16(data, pos)? as u16;
            let ext_len = be16(data, pos + 2)?;
            pos += 4;
            if ext_type == EXT_KEY_SHARE && pos + 2 <= ext_end {
                let shares_end = (pos + 2 + be16(data, pos)?).min(ext_end);
                let mut off = pos + 2;
                while off + 4 <= shares_end {
                    let group = be16(data, off)? as u16;
                    let key_len = be16(data, off + 2)?;
                    off += 4 + key_len;
                    if off <= shares_end && !key_shares.iter().any(|(g, _)| *g == group) {
                        key_shares.push((group, key_len));
                    }
                }
            }
            pos += ext_len;
        }
        Some(ClientHelloInfo {
            cipher_suites: suites,
            key_shares,
        })
    }
    inner(data).unwrap_or_default()
}

fn select_cipher_suite(info: &ClientHelloInfo) -> u16 {
    CIPHER_PREFERENCE
        .iter()
        .copied()
        .find(|s| info.cipher_suites.contains(s))
        .unwrap_or(CIPHER_PREFERENCE[0])
}

fn x25519_public_key() -> [u8; 32] {
    use ring::agreement::{EphemeralPrivateKey, X25519};
    let rng = ring::rand::SystemRandom::new();
    if let Ok(k) = EphemeralPrivateKey::generate(&X25519, &rng) {
        if let Ok(p) = k.compute_public_key() {
            if let Ok(arr) = <[u8; 32]>::try_from(p.as_ref()) {
                return arr;
            }
        }
    }
    // Настоящие ключи — элементы поля меньше 2^255: старший бит сброшен.
    let mut key = [0u8; X25519_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key[X25519_KEY_LEN - 1] &= 0x7f;
    key
}

fn server_key_share(info: &ClientHelloInfo) -> (u16, Vec<u8>) {
    // Гибридную постквантовую группу зеркалим, если клиент её предложил, как
    // браузеры и серверы; ключей из неё клиент не выводит.
    if info.key_share_len(GROUP_X25519MLKEM768) == Some(X25519MLKEM768_CLIENT_SHARE_LEN) {
        let mut v = vec![0u8; MLKEM768_CIPHERTEXT_LEN];
        rand::thread_rng().fill_bytes(&mut v);
        v.extend_from_slice(&x25519_public_key());
        return (GROUP_X25519MLKEM768, v);
    }
    (GROUP_X25519, x25519_public_key().to_vec())
}

fn push_u16(v: &mut Vec<u8>, x: usize) {
    v.extend_from_slice(&(x as u16).to_be_bytes());
}

/// ServerHello + CCS + одна ApplicationData-запись. Клиенты Telegram
/// разбирают ровно эти три записи и проверяют HMAC по всем, поэтому форма
/// неизменна, а размеры могут меняться.
fn build_server_hello(
    secret: &[u8],
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    info: &ClientHelloInfo,
    appdata_len: usize,
) -> Vec<u8> {
    let (group, key_exchange) = server_key_share(info);
    let mut ext = Vec::with_capacity(16 + key_exchange.len());
    push_u16(&mut ext, EXT_SUPPORTED_VERSIONS as usize);
    push_u16(&mut ext, 2);
    push_u16(&mut ext, 0x0304);
    push_u16(&mut ext, EXT_KEY_SHARE as usize);
    push_u16(&mut ext, 4 + key_exchange.len());
    push_u16(&mut ext, group as usize);
    push_u16(&mut ext, key_exchange.len());
    ext.extend_from_slice(&key_exchange);

    let mut body = Vec::with_capacity(80 + ext.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    push_u16(&mut body, select_cipher_suite(info) as usize);
    body.push(0x00);
    push_u16(&mut body, ext.len());
    body.extend_from_slice(&ext);

    let mut out = Vec::with_capacity(9 + body.len() + CCS_FRAME.len() + 5 + appdata_len);
    out.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 0x03, 0x03]);
    push_u16(&mut out, 4 + body.len());
    out.push(0x02);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&body);
    out.extend_from_slice(&CCS_FRAME);
    out.extend_from_slice(&[TLS_RECORD_APPDATA, 0x03, 0x03]);
    push_u16(&mut out, appdata_len);
    let start = out.len();
    out.resize(start + appdata_len, 0);
    rand::thread_rng().fill_bytes(&mut out[start..]);

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(client_random);
    mac.update(&out);
    let server_random = mac.finalize().into_bytes();
    out[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&server_random);
    out
}

fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / TLS_APPDATA_MAX + 1));
    for chunk in data.chunks(TLS_APPDATA_MAX) {
        out.extend_from_slice(&[TLS_RECORD_APPDATA, 0x03, 0x03]);
        push_u16(&mut out, chunk.len());
        out.extend_from_slice(chunk);
    }
    out
}

// ---------------------------------------------------------------------------
// Потоки записей
// ---------------------------------------------------------------------------

/// Снимает TLS-записи с входящего потока. Состояние (частично прочитанный
/// заголовок, остаток записи) хранится в структуре, поэтому `Pending` в
/// середине записи ничего не теряет. Прежняя версия собирала future заново
/// на каждом poll и теряла уже прочитанные байты заголовка.
struct TlsRecordReader<R> {
    inner: R,
    hdr: [u8; 5],
    hdr_filled: usize,
    /// Байт полезной нагрузки текущей AppData-записи.
    read_left: usize,
    /// Байт CCS-записи, которые надо выбросить.
    skip_left: usize,
    eof: bool,
}

impl<R> TlsRecordReader<R> {
    fn new(inner: R) -> Self {
        TlsRecordReader {
            inner,
            hdr: [0u8; 5],
            hdr_filled: 0,
            read_left: 0,
            skip_left: 0,
            eof: false,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for TlsRecordReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.read_left > 0 {
                let want = this.read_left.min(buf.remaining());
                let got = {
                    let mut limited = buf.take(want);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
                    limited.filled().len()
                };
                // SAFETY: inner записал `got` байт в начало незаполненной части buf.
                unsafe { buf.assume_init(got) };
                buf.advance(got);
                if got == 0 {
                    // Обрыв посреди записи — как b'' в десктопе: конец потока.
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.read_left -= got;
                return Poll::Ready(Ok(()));
            }
            if this.skip_left > 0 {
                let mut junk = [0u8; 64];
                let n = this.skip_left.min(junk.len());
                let mut jb = ReadBuf::new(&mut junk[..n]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut jb))?;
                let got = jb.filled().len();
                if got == 0 {
                    return Poll::Ready(Err(faketls_eof()));
                }
                this.skip_left -= got;
                continue;
            }
            while this.hdr_filled < 5 {
                let mut hb = ReadBuf::new(&mut this.hdr[this.hdr_filled..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut hb))?;
                let got = hb.filled().len();
                if got == 0 {
                    if this.hdr_filled == 0 {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(faketls_eof()));
                }
                this.hdr_filled += got;
            }
            this.hdr_filled = 0;
            let rtype = this.hdr[0];
            let rec_len = u16::from_be_bytes([this.hdr[3], this.hdr[4]]) as usize;
            match rtype {
                TLS_RECORD_CCS => this.skip_left = rec_len,
                TLS_RECORD_APPDATA => this.read_left = rec_len,
                _ => {
                    // Alert или что угодно ещё — конец потока, как в десктопе.
                    this.eof = true;
                }
            }
        }
    }
}

fn faketls_eof() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "faketls eof")
}

/// Заворачивает исходящие данные в AppData-записи. `Ready(Ok(n))`
/// возвращается только когда запись целиком ушла в сокет: мосты не вызывают
/// flush, и данные не должны застревать в буфере. Прежняя версия при частичной
/// записи возвращала число байт обёртки и ломала поток.
struct TlsRecordWriter<W> {
    inner: W,
    pending: Vec<u8>,
    pos: usize,
    /// Сколько байт открытых данных в `pending`.
    pending_plain: usize,
}

impl<W> TlsRecordWriter<W> {
    fn new(inner: W) -> Self {
        TlsRecordWriter {
            inner,
            pending: Vec::new(),
            pos: 0,
            pending_plain: 0,
        }
    }
}

impl<W: AsyncWrite + Unpin> TlsRecordWriter<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pos < self.pending.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.pos += n;
        }
        self.pending.clear();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TlsRecordWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(TLS_APPDATA_MAX);
            this.pending = wrap_tls_record(&buf[..n]);
            this.pos = 0;
            this.pending_plain = n;
        }
        // После Pending вызывающий повторяет тот же буфер (write_all, copy):
        // дописываем начатую запись и отчитываемся за её открытые байты.
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.pending_plain)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Рукопожатие
// ---------------------------------------------------------------------------

pub async fn server_handshake(
    mut conn: TcpStream,
    first: u8,
    secret: &[u8],
    masking: &str,
    label: &str,
) -> Option<FakeTlsStream> {
    let mut hdr_rest = [0u8; 4];
    match tokio::time::timeout(READ_HANDSHAKE_TIMEOUT, conn.read_exact(&mut hdr_rest)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record header", label));
            return None;
        }
    }

    let mut tls_header = [0u8; 5];
    tls_header[0] = first;
    tls_header[1..5].copy_from_slice(&hdr_rest);
    let record_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;

    let mut body = vec![0u8; record_len];
    match tokio::time::timeout(READ_RECORD_TIMEOUT, conn.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record body", label));
            return None;
        }
    }

    let mut client_hello = Vec::with_capacity(5 + record_len);
    client_hello.extend_from_slice(&tls_header);
    client_hello.extend_from_slice(&body);

    let verified = verify_client_hello(&client_hello, secret);
    // Записанный hello валиден минутами; ответить на него снова — значит
    // показать активному зонду, что здесь прокси, а не маскирующий сайт.
    let replayed = match &verified {
        Some((client_random, _, _)) => !REPLAY_CACHE.lock().first_seen(client_random, Instant::now()),
        None => false,
    };

    let (client_random, session_id, ts) = match verified {
        Some(v) if !replayed => v,
        _ => {
            log_debug(&format!(
                "[{}] Fake TLS {} (size={} rec={}) -> masking",
                label,
                if replayed { "hello replayed" } else { "verify failed" },
                client_hello.len(),
                record_len
            ));
            proxy_to_masking_domain(conn, client_hello, masking, label).await;
            return None;
        }
    };

    log_debug(&format!("[{}] Fake TLS handshake ok (ts={})", label, ts));
    let info = parse_client_hello(&client_hello);
    let server_hello = build_server_hello(secret, &client_random, &session_id, &info, appdata_len());
    let delay = rand::thread_rng().gen_range(SERVER_HELLO_DELAY_MS.0..=SERVER_HELLO_DELAY_MS.1);
    tokio::time::sleep(Duration::from_millis(delay)).await;
    if conn.write_all(&server_hello).await.is_err() {
        return None;
    }
    let _ = conn.flush().await;

    let (r, w) = tokio::io::split(conn);
    Some(FakeTlsStream {
        read: Box::new(TlsRecordReader::<ReadHalf<TcpStream>>::new(r)),
        write: Box::new(TlsRecordWriter::<WriteHalf<TcpStream>>::new(w)),
    })
}

async fn proxy_to_masking_domain(conn: TcpStream, initial: Vec<u8>, domain: &str, label: &str) {
    let upstream = match tokio::time::timeout(
        MASKING_CONNECT_TIMEOUT,
        TcpStream::connect((domain, 443u16)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            log_warn(&format!("[{}] masking: cannot connect to {}:443", label, domain));
            return;
        }
    };

    log_debug(&format!("[{}] masking -> {}:443", label, domain));
    STATS.connections_masked.fetch_add(1, Ordering::Relaxed);

    let mut upstream = upstream;
    if upstream.write_all(&initial).await.is_err() {
        return;
    }

    let (mut c_read, mut c_write) = tokio::io::split(conn);
    let (mut u_read, mut u_write) = tokio::io::split(upstream);

    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut c_read, &mut u_write).await;
        let _ = u_write.shutdown().await;
    });
    let down = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut u_read, &mut c_write).await;
        let _ = c_write.shutdown().await;
    });

    let _ = tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const TELEGRAM_SUITES: [u16; 5] = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f];
    const TELEGRAM_SHARES: [(u16, usize); 2] = [
        (GROUP_X25519MLKEM768, X25519MLKEM768_CLIENT_SHARE_LEN),
        (GROUP_X25519, X25519_KEY_LEN),
    ];

    fn now_unix() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    fn sign(mut body: Vec<u8>, secret: &[u8], ts: i64) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&body);
        let d = mac.finalize().into_bytes();
        let mut cr = [0u8; 32];
        cr.copy_from_slice(&d[..32]);
        let tsb = (ts as u32).to_le_bytes();
        for i in 0..4 {
            cr[28 + i] = d[28 + i] ^ tsb[i];
        }
        body[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 32].copy_from_slice(&cr);
        body
    }

    fn rand_bytes(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        rand::thread_rng().fill_bytes(&mut v);
        v
    }

    fn structured_hello(suites: &[u16], shares: &[(u16, usize)], ts: i64) -> Vec<u8> {
        let mut ksl = Vec::new();
        for (g, l) in shares {
            push_u16(&mut ksl, *g as usize);
            push_u16(&mut ksl, *l);
            ksl.extend(rand_bytes(*l));
        }
        let mut ext = Vec::new();
        push_u16(&mut ext, 0);
        push_u16(&mut ext, 0);
        push_u16(&mut ext, EXT_KEY_SHARE as usize);
        push_u16(&mut ext, 2 + ksl.len());
        push_u16(&mut ext, ksl.len());
        ext.extend(&ksl);
        push_u16(&mut ext, EXT_SUPPORTED_VERSIONS as usize);
        push_u16(&mut ext, 3);
        ext.extend([2, 0x03, 0x04]);
        let mut hello = vec![0x03, 0x03];
        hello.extend([0u8; 32]);
        hello.push(0x20);
        hello.extend(rand_bytes(32));
        push_u16(&mut hello, 2 * suites.len());
        for s in suites {
            push_u16(&mut hello, *s as usize);
        }
        hello.extend([0x01, 0x00]);
        push_u16(&mut hello, ext.len());
        hello.extend(&ext);
        let mut msg = vec![0x01];
        msg.extend(&(hello.len() as u32).to_be_bytes()[1..]);
        msg.extend(&hello);
        let mut body = vec![0x16, 0x03, 0x01];
        push_u16(&mut body, msg.len());
        body.extend(&msg);
        sign(body, &SECRET, ts)
    }

    fn telegram_hello() -> Vec<u8> {
        structured_hello(&TELEGRAM_SUITES, &TELEGRAM_SHARES, now_unix())
    }

    fn split_records(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
            out.push((data[pos], data[pos + 5..pos + 5 + len].to_vec()));
            pos += 5 + len;
        }
        out
    }

    /// (cipher, [(ext_type, data)]) из handshake-сообщения ServerHello.
    fn sh_fields(rec: &[u8]) -> (u16, Vec<(u16, Vec<u8>)>) {
        let mut pos = 4 + 2 + 32;
        pos += 1 + rec[pos] as usize;
        let cipher = be16(rec, pos).unwrap() as u16;
        pos += 3;
        let ext_end = pos + 2 + be16(rec, pos).unwrap();
        pos += 2;
        let mut exts = Vec::new();
        while pos < ext_end {
            let t = be16(rec, pos).unwrap() as u16;
            let l = be16(rec, pos + 2).unwrap();
            exts.push((t, rec[pos + 4..pos + 4 + l].to_vec()));
            pos += 4 + l;
        }
        (cipher, exts)
    }

    fn build(hello: &[u8], appdata: usize) -> Vec<u8> {
        let (cr, sid, _) = verify_client_hello(hello, &SECRET).expect("verifies");
        build_server_hello(&SECRET, &cr, &sid, &parse_client_hello(hello), appdata)
    }

    #[test]
    fn verify_accepts_structured_and_rejects_others() {
        let h = telegram_hello();
        assert!(verify_client_hello(&h, &SECRET).is_some());
        assert!(verify_client_hello(&h, &[1u8; 16]).is_none());
        let stale = structured_hello(&TELEGRAM_SUITES, &TELEGRAM_SHARES, now_unix() - 1000);
        assert!(verify_client_hello(&stale, &SECRET).is_none());
        let mut t = h.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(verify_client_hello(&t, &SECRET).is_none());
        assert!(verify_client_hello(&h[..42], &SECRET).is_none());
    }

    #[test]
    fn parse_extracts_suites_and_shares() {
        let info = parse_client_hello(&telegram_hello());
        assert_eq!(info.cipher_suites, TELEGRAM_SUITES.to_vec());
        assert_eq!(info.key_shares, TELEGRAM_SHARES.to_vec());
    }

    #[test]
    fn parse_malformed_is_empty_and_never_panics() {
        let h = telegram_hello();
        for cut in [0, 10, 43, 44, 80, 120, h.len() - 1] {
            let info = parse_client_hello(&h[..cut]);
            let _ = info.key_shares.len();
        }
        assert!(parse_client_hello(&h[..60]).cipher_suites.is_empty());
        // Неструктурированный hello старого образца (517 байт нулей).
        let mut old = vec![0u8; 517];
        old[0] = 0x16;
        old[5] = 0x01;
        old[43] = 0x20;
        let _ = parse_client_hello(&old);
        for _ in 0..200 {
            let _ = parse_client_hello(&rand_bytes(300));
        }
    }

    #[test]
    fn flight_is_three_records_and_hmac_covers_it() {
        let h = telegram_hello();
        let resp = build(&h, 100);
        let recs = split_records(&resp);
        assert_eq!(
            recs.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![TLS_RECORD_HANDSHAKE, TLS_RECORD_CCS, TLS_RECORD_APPDATA]
        );
        assert_eq!(recs[2].1.len(), 100);
        let (cr, sid, _) = verify_client_hello(&h, &SECRET).unwrap();
        assert_eq!(&resp[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32], &sid);
        let mut z = resp.clone();
        z[11..43].fill(0);
        let mut mac = HmacSha256::new_from_slice(&SECRET).unwrap();
        mac.update(&cr);
        mac.update(&z);
        assert_eq!(&resp[11..43], mac.finalize().into_bytes().as_slice());
    }

    #[test]
    fn mirrors_post_quantum_group() {
        let recs = split_records(&build(&telegram_hello(), 64));
        let (cipher, exts) = sh_fields(&recs[0].1);
        assert_eq!(cipher, 0x1301);
        assert_eq!(exts[0], (EXT_SUPPORTED_VERSIONS, vec![0x03, 0x04]));
        let ks = &exts[1];
        assert_eq!(ks.0, EXT_KEY_SHARE);
        assert_eq!(be16(&ks.1, 0).unwrap() as u16, GROUP_X25519MLKEM768);
        assert_eq!(be16(&ks.1, 2).unwrap(), MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN);
    }

    #[test]
    fn falls_back_to_x25519_and_ignores_wrong_pq_size() {
        for shares in [
            vec![(GROUP_X25519, X25519_KEY_LEN)],
            vec![(GROUP_X25519MLKEM768, 1000), (GROUP_X25519, X25519_KEY_LEN)],
        ] {
            let h = structured_hello(&TELEGRAM_SUITES, &shares, now_unix());
            let (_, exts) = sh_fields(&split_records(&build(&h, 64))[0].1);
            assert_eq!(be16(&exts[1].1, 0).unwrap() as u16, GROUP_X25519);
            assert_eq!(be16(&exts[1].1, 2).unwrap(), X25519_KEY_LEN);
            assert!(exts[1].1[4 + 31] & 0x80 == 0);
        }
    }

    #[test]
    fn picks_cipher_offered_by_client() {
        let h = structured_hello(&[0x1302, 0x1303], &TELEGRAM_SHARES, now_unix());
        let (cipher, _) = sh_fields(&split_records(&build(&h, 64))[0].1);
        assert_eq!(cipher, 0x1303);
    }

    #[test]
    fn telegram_flight_matches_telemt_size() {
        // telemt отвечал клиентам Telegram ровно 1290 байтами при записи сайта
        // меньше 64 байт (тест десктопа).
        // Глобальный профиль не трогаем: тесты идут параллельно.
        assert_eq!(build(&telegram_hello(), clamp_profile(Some(30))).len(), 1290);
    }

    #[test]
    fn profile_is_clamped_and_fallback_in_range() {
        assert_eq!(clamp_profile(Some(10)), APPDATA_MIN);
        assert_eq!(clamp_profile(Some(1_000_000)), TLS_APPDATA_MAX);
        assert_eq!(clamp_profile(Some(3000)), 3000);
        assert_eq!(clamp_profile(None), 0);
        let mut sizes = HashSet::new();
        for _ in 0..200 {
            let n = fallback_appdata_len();
            assert!((FALLBACK_APPDATA_RANGE.0..=FALLBACK_APPDATA_RANGE.1).contains(&n));
            sizes.insert(n);
        }
        assert!(sizes.len() > 1);
    }

    #[test]
    fn first_appdata_len_cases() {
        fn rec(t: u8, n: usize) -> Vec<u8> {
            let mut v = vec![t, 3, 3];
            push_u16(&mut v, n);
            v.extend(vec![0u8; n]);
            v
        }
        let mut f = rec(TLS_RECORD_HANDSHAKE, 122);
        f.extend(rec(TLS_RECORD_CCS, 1));
        assert_eq!(first_appdata_record_len(&f), None);
        f.extend(rec(TLS_RECORD_APPDATA, 27));
        f.extend(rec(TLS_RECORD_APPDATA, 3000));
        assert_eq!(first_appdata_record_len(&f), Some(27));
        assert_eq!(first_appdata_record_len(&rec(0x15, 2)), Some(0));
    }

    #[test]
    fn replay_cache_semantics() {
        let t0 = Instant::now();
        let w = Duration::from_secs(10);
        let mut c = ReplayCache::new(w, 8);
        assert!(c.first_seen(&[1; 32], t0));
        assert!(!c.first_seen(&[1; 32], t0));
        assert!(c.first_seen(&[2; 32], t0));
        // Ещё повтор за миг до истечения, новый — после.
        assert!(!c.first_seen(&[1; 32], t0 + Duration::from_millis(9999)));
        assert!(c.first_seen(&[1; 32], t0 + Duration::from_secs(11)));
        assert!(!c.first_seen(&[1; 32], t0 + Duration::from_secs(11)));

        let mut c = ReplayCache::new(w, 2);
        assert!(c.first_seen(&[1; 32], t0));
        assert!(c.first_seen(&[2; 32], t0));
        // Живая запись не вытесняется до проверки.
        assert!(!c.first_seen(&[1; 32], t0));
        assert!(c.first_seen(&[3; 32], t0));
        assert_eq!(c.len(), 2);
        assert!(!c.first_seen(&[2; 32], t0));
        assert!(!c.first_seen(&[3; 32], t0));
        assert!(c.first_seen(&[1; 32], t0));
        assert!(REPLAY_WINDOW >= Duration::from_secs(2 * TIMESTAMP_TOLERANCE as u64));
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (a, b) = tokio::join!(TcpStream::connect(addr), l.accept());
        (a.unwrap(), b.unwrap().0)
    }

    #[tokio::test]
    async fn handshake_then_replay_goes_to_masking() {
        // Маскирующий «сайт» — локальный порт 443 недоступен, поэтому
        // проверяем, что на повтор прокси не отвечает ServerHello.
        let hello = telegram_hello();
        let (mut client, server) = pair().await;
        let h2 = hello.clone();
        let srv = tokio::spawn(async move {
            server_handshake(server, h2[0], &SECRET, "127.0.0.1", "t").await.is_some()
        });
        client.write_all(&hello[1..]).await.unwrap();
        let mut hdr = [0u8; 5];
        client.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0], TLS_RECORD_HANDSHAKE);
        assert!(srv.await.unwrap());

        let (mut client, server) = pair().await;
        let h2 = hello.clone();
        let srv = tokio::spawn(async move {
            server_handshake(server, h2[0], &SECRET, "127.0.0.1", "t").await.is_some()
        });
        client.write_all(&hello[1..]).await.unwrap();
        assert!(!srv.await.unwrap());
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut b))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0, "на повтор не должно быть ServerHello");
    }

    /// Поток, отдающий данные по одному байту и Pending между ними.
    struct Trickle {
        data: Vec<u8>,
        pos: usize,
        flip: bool,
    }

    impl AsyncRead for Trickle {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flip = !self.flip;
            if self.flip {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if self.pos < self.data.len() {
                let b = self.data[self.pos];
                buf.put_slice(&[b]);
                self.pos += 1;
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn reader_survives_pending_inside_headers() {
        let mut wire = CCS_FRAME.to_vec();
        wire.extend(wrap_tls_record(b"hello "));
        wire.extend(wrap_tls_record(&vec![7u8; 20000]));
        wire.extend([0x15, 3, 3, 0, 2, 1, 0]);
        let mut r = TlsRecordReader::new(Trickle { data: wire, pos: 0, flip: false });
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        let mut want = b"hello ".to_vec();
        want.extend(vec![7u8; 20000]);
        assert_eq!(out, want);
    }

    /// Писатель, принимающий не больше 3 байт за раз и Pending через раз.
    struct SlowSink {
        out: Vec<u8>,
        flip: bool,
    }

    impl AsyncWrite for SlowSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.flip = !self.flip;
            if self.flip {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = buf.len().min(3);
            self.out.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn writer_keeps_framing_on_partial_writes() {
        let mut w = TlsRecordWriter::new(SlowSink { out: Vec::new(), flip: false });
        let payload: Vec<u8> = (0..40000u32).map(|i| i as u8).collect();
        w.write_all(&payload).await.unwrap();
        assert!(w.pending.is_empty(), "после write_all ничего не ждёт flush");
        let wire = w.inner.out.clone();
        let mut r = TlsRecordReader::new(&wire[..]);
        let mut back = Vec::new();
        r.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, payload);
        assert_eq!(wire.len(), payload.len() + 5 * 3);
    }

    #[test]
    fn probe_hello_is_tls13_with_x25519() {
        let h = probe_client_hello("example.com").expect("hello");
        assert_eq!(h[0], TLS_RECORD_HANDSHAKE);
        assert_eq!(h[5], 0x01);
        let info = parse_client_hello(&h);
        assert_eq!(info.key_share_len(GROUP_X25519), Some(X25519_KEY_LEN));
        assert!(info.cipher_suites.contains(&0x1301));
    }

    #[tokio::test]
    async fn probe_reads_first_appdata_record() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 4096];
            let _ = s.read(&mut b).await;
            let mut f = vec![0x16, 3, 3, 0, 4, 2, 0, 0, 0];
            f.extend(CCS_FRAME);
            // Запись приходит по частям: заголовок отдельно.
            s.write_all(&f).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            s.write_all(&[0x17, 3, 3, 0x01, 0x2c]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        assert_eq!(probe_appdata_len("127.0.0.1", port, Duration::from_secs(3)).await, Some(300));
    }

    #[tokio::test]
    async fn probe_unreachable_or_silent_gives_none() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        assert_eq!(probe_appdata_len("127.0.0.1", port, Duration::from_secs(1)).await, None);

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(s);
        });
        let t = Instant::now();
        assert_eq!(probe_appdata_len("127.0.0.1", port, Duration::from_millis(500)).await, None);
        assert!(t.elapsed() < Duration::from_secs(2));
        hold.abort();
    }
}
