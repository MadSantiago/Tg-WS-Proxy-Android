// ---------------------------------------------------------------------------
// HTTP/2-мультиплексирование медиа через CF — порт proxy/cf_h2.py и
// proxy/h2_transport.py десктопа (v1.11.0 48954ff, v1.11.1 f742a89,
// v1.11.2 59c3a6e, 3cda0f5).
//
// Три уровня, как на десктопе:
//   * H2Pool — карта host → Lane, host = kws{dc}.{cf_domain};
//   * Lane — одно TCP+TLS-соединение с ALPN h2, до 64 запросов;
//   * Channel — одно клиентское соединение Telegram, до 8 запросов.
// Каждый транспортный пакет MTProto клиента уходит отдельным POST /api,
// тело ответа — один пакет для клиента.
//
// Отличия от десктопа:
//   * open не ждёт preflight: без готового lane соединение сразу идёт по WS,
//     preflight выполняется в фоне (H2Pool::try_open);
//   * cooldown домена и DC растёт: 30 с, удвоение, потолок 30 мин; сброс при
//     смене сети (ProxyPools::apply_network_change);
//   * задача повторов спит на Notify и ставит таймер только на ближайший срок,
//     без опроса раз в 0,25 с; тайминги — профиль Wi-Fi/сотовая из config.rs;
//   * бюджет буферов ответов на lane 8 МБ вместо 32 МБ;
//   * lane закрывается после 60 с без каналов;
//   * H2 всегда на 443 с TLS, независимо от DISABLE_SECURE.
// Диагностические логи десктопа (H2 WAIT/SLOW/FLOW/DETAIL) не перенесены.
// ---------------------------------------------------------------------------

use crate::config::*;
use crate::crypto::{
    proto_tag_to_type, transport_header, transport_header_len, TrackedStream, PROTO_ABRIDGED,
    PROTO_PADDED_INTERMEDIATE,
};
use crate::{ldebug, linfo, lwarn};
use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use rand::Rng;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Константы (cf_h2.py, h2_transport.py)
// ---------------------------------------------------------------------------

pub const MAX_PACKET: usize = 4 * 1024 * 1024;
/// 59c3a6e: Android и MTProtoKit дополняют незашифрованные пакеты до 256 байт.
pub const MAX_PLAIN_PADDING: usize = 256;
const MAX_CIPHER_PADDING: usize = 15;
const MIN_PACKET: usize = 24;
const REPLY_QUEUE: usize = 16;
const REPLAY_HISTORY_BYTES: usize = 64 * 1024;
const REPLAY_HISTORY_PACKETS: usize = 16;
const MAX_CHANNEL_REPLAYS: usize = 2;
const REPLAY_MAX_ATTEMPTS: u32 = 3;
const STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
const IO_BATCH_SIZE: usize = 64 * 1024;
const H2_PORT: u16 = 443;
/// Повторная проверка повтора, упёршегося в ёмкость (десктоп опрашивал
/// раз в 0,25 с всегда; здесь — только в этом состоянии).
const BLOCKED_REPLAY_RETRY: Duration = Duration::from_millis(250);

/// Лимиты и тайминги. В рабочем режиме — `H2Limits::default()`; тесты
/// уменьшают их так же, как десктопные тесты патчат константы модуля.
#[derive(Clone, Debug)]
pub struct H2Limits {
    pub channel_requests: usize,
    pub channel_bytes: usize,
    pub lane_requests: usize,
    pub lane_bytes: usize,
    /// Десктоп: 32 МБ. Здесь 8 МБ.
    pub lane_reply_bytes: usize,
    pub max_packet: usize,
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    pub setup_timeout: Duration,
    pub lane_idle: Duration,
    pub cooldown_initial: Duration,
    pub cooldown_max: Duration,
    /// None — профиль по типу сети (config::h2_replay_timing).
    pub replay: Option<H2ReplayTiming>,
}

impl Default for H2Limits {
    fn default() -> Self {
        H2Limits {
            channel_requests: 8,
            channel_bytes: 8 * 1024 * 1024,
            lane_requests: 64,
            lane_bytes: 32 * 1024 * 1024,
            lane_reply_bytes: 8 * 1024 * 1024,
            max_packet: MAX_PACKET,
            request_timeout: Duration::from_secs(65),
            connect_timeout: Duration::from_secs(8),
            setup_timeout: Duration::from_secs(8),
            lane_idle: Duration::from_secs(60),
            cooldown_initial: Duration::from_secs(30),
            cooldown_max: Duration::from_secs(30 * 60),
            replay: None,
        }
    }
}

impl H2Limits {
    fn timing(&self) -> H2ReplayTiming {
        self.replay.unwrap_or_else(h2_replay_timing)
    }
}

// ---------------------------------------------------------------------------
// Ошибки
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum H2Error {
    /// _MTProtoTransportError (f742a89): код уходит клиенту пакетом, канал
    /// закрывается, домен в cooldown не попадает.
    Transport(i32),
    /// Неожиданный HTTP-статус (ConnectionError на десктопе).
    Http(String),
    /// Нарушение протокола, неверный ответ (ValueError, ошибки h2).
    Protocol(String),
    Io(String),
    Timeout(&'static str),
    /// Ответ больше лимита пакета или очереди канала (BufferError).
    Buffer(String),
    /// Бюджет буферов ответов lane (_ReplyBufferFull): домен не виноват.
    ReplyBufferFull,
    Closed(&'static str),
}

impl std::fmt::Display for H2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H2Error::Transport(c) => write!(f, "MTProto transport error {}", c),
            H2Error::Http(s) | H2Error::Protocol(s) | H2Error::Io(s) | H2Error::Buffer(s) => {
                f.write_str(s)
            }
            H2Error::Timeout(s) => write!(f, "{} timed out", s),
            H2Error::ReplyBufferFull => f.write_str("H2 lane response buffers exceeded bound"),
            H2Error::Closed(s) => f.write_str(s),
        }
    }
}

impl From<h2::Error> for H2Error {
    fn from(e: h2::Error) -> Self {
        if e.is_io() {
            H2Error::Io(e.to_string())
        } else {
            H2Error::Protocol(format!("h2: {}", e))
        }
    }
}

// ---------------------------------------------------------------------------
// Разбор и сборка транспортных пакетов клиента
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum PacketError {
    Io(std::io::Error),
    Invalid(String),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::Io(e) => write!(f, "{}", e),
            PacketError::Invalid(s) => f.write_str(s),
        }
    }
}

impl From<std::io::Error> for PacketError {
    fn from(e: std::io::Error) -> Self {
        PacketError::Io(e)
    }
}

async fn read_plain<R: AsyncRead + Unpin>(
    reader: &mut R,
    dec: &mut TrackedStream,
    buf: &mut [u8],
) -> std::io::Result<()> {
    reader.read_exact(buf).await?;
    dec.xor(buf);
    Ok(())
}

/// Порт `_read_packet`: читает один транспортный пакет клиента, снимает
/// обфускацию (`dec` = clt_dec) и рамку протокола. Возвращает тело пакета
/// MTProto и флаг quick ack. `proto_type` — crypto::PROTO_*.
pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    dec: &mut TrackedStream,
    proto_type: i32,
    max_packet: usize,
) -> Result<(Vec<u8>, bool), PacketError> {
    let mut head = [0u8; 4];
    read_plain(reader, dec, &mut head[..1]).await?;
    let header_len = transport_header_len(proto_type, head[0]);
    if header_len > 1 {
        read_plain(reader, dec, &mut head[1..header_len]).await?;
    }
    let header = transport_header(proto_type, &head[..header_len])
        .ok_or_else(|| PacketError::Invalid("short transport header".into()))?;
    let padded = proto_type == PROTO_PADDED_INTERMEDIATE;
    let length = header.payload_len;
    let limit = max_packet + if padded { MAX_PLAIN_PADDING } else { 0 };
    if !(MIN_PACKET..=limit).contains(&length) {
        return Err(PacketError::Invalid(format!(
            "native packet length outside supported range: {}",
            length
        )));
    }
    let mut body = vec![0u8; length];
    read_plain(reader, dec, &mut body).await?;
    if padded {
        let (packet_length, max_padding) = if body[..8] == [0u8; 8] {
            let declared = u32::from_le_bytes([body[16], body[17], body[18], body[19]]);
            (20u64 + declared as u64, MAX_PLAIN_PADDING)
        } else {
            (
                (MIN_PACKET + ((length - MIN_PACKET) / 16) * 16) as u64,
                MAX_CIPHER_PADDING,
            )
        };
        if packet_length < MIN_PACKET as u64
            || packet_length > length as u64
            || length as u64 - packet_length > max_padding as u64
        {
            return Err(PacketError::Invalid(format!(
                "invalid padded native packet: frame={} packet={} limit={}",
                length, packet_length, max_padding
            )));
        }
        body.truncate(packet_length as usize);
    }
    if body.len() & 3 != 0 || body.len() > max_packet {
        return Err(PacketError::Invalid(
            "invalid native packet alignment or size".into(),
        ));
    }
    Ok((body, header.quick))
}

/// Порт `_encode_reply`: оборачивает пакет MTProto в рамку протокола клиента
/// (padded intermediate — со случайным дополнением 0–3 байта).
pub fn encode_reply(body: &[u8], proto_type: i32, max_packet: usize) -> Result<Vec<u8>, String> {
    if body.is_empty() || body.len() & 3 != 0 || body.len() > max_packet {
        return Err(format!("invalid HTTP MTProto response length: {}", body.len()));
    }
    if proto_type == PROTO_ABRIDGED {
        let words = body.len() / 4;
        let mut out = Vec::with_capacity(body.len() + 4);
        if words < 0x7F {
            out.push(words as u8);
        } else {
            out.push(0x7F);
            out.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
        out.extend_from_slice(body);
        return Ok(out);
    }
    let mut rng = rand::thread_rng();
    let padding = if proto_type == PROTO_PADDED_INTERMEDIATE {
        rng.gen_range(0..4usize)
    } else {
        0
    };
    let mut out = Vec::with_capacity(4 + body.len() + padding);
    out.extend_from_slice(&((body.len() + padding) as u32).to_le_bytes());
    out.extend_from_slice(body);
    for _ in 0..padding {
        out.push(rng.gen());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Cooldown с ростом
// ---------------------------------------------------------------------------

pub struct Cooldowns {
    map: Mutex<HashMap<String, (u32, Instant)>>,
    initial: Duration,
    max: Duration,
}

impl Cooldowns {
    pub fn new(initial: Duration, max: Duration) -> Self {
        Cooldowns {
            map: Mutex::new(HashMap::new()),
            initial,
            max,
        }
    }

    pub fn active(&self, key: &str, now: Instant) -> bool {
        self.map.lock().get(key).is_some_and(|(_, until)| now < *until)
    }

    /// Возвращает длительность нового cooldown: 30 с, 60 с, 120 с … ≤ max.
    pub fn record_failure(&self, key: &str, now: Instant) -> Duration {
        let mut map = self.map.lock();
        let entry = map.entry(key.to_string()).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        let shift = (entry.0 - 1).min(16);
        let d = self.initial.saturating_mul(1u32 << shift).min(self.max);
        entry.1 = now + d;
        d
    }

    pub fn record_success(&self, key: &str) {
        let mut map = self.map.lock();
        if !map.is_empty() {
            map.remove(key);
        }
    }

    pub fn clear(&self) {
        self.map.lock().clear();
    }
}

// ---------------------------------------------------------------------------
// Соединение (h2_transport.py)
// ---------------------------------------------------------------------------

pub trait H2Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> H2Io for T {}
pub type BoxIo = Box<dyn H2Io>;
pub type ConnectFuture<'a> = Pin<Box<dyn Future<Output = Result<BoxIo, H2Error>> + Send + 'a>>;

/// Откуда lane берёт транспорт. Рабочий — CfTlsConnector; тесты подставляют
/// локальный h2-сервер поверх tokio::io::duplex.
pub trait Connector: Send + Sync + 'static {
    fn connect<'a>(&'a self, host: &'a str) -> ConnectFuture<'a>;
}

/// TCP :443 к host (при неудаче системного DNS — через DoH, как
/// cf_connect_domain), TLS с проверкой и ALPN h2.
pub struct CfTlsConnector;

impl Connector for CfTlsConnector {
    fn connect<'a>(&'a self, host: &'a str) -> ConnectFuture<'a> {
        Box::pin(async move {
            let tcp = match tokio::net::TcpStream::connect((host, H2_PORT)).await {
                Ok(s) => s,
                Err(e) => match crate::cfproxy::resolve_doh(host).await {
                    Some(ip) if !ip.is_empty() => {
                        ldebug!(" H2 DNS {} -> {}", host, ip);
                        tokio::net::TcpStream::connect((ip.as_str(), H2_PORT))
                            .await
                            .map_err(|e| H2Error::Io(e.to_string()))?
                    }
                    _ => return Err(H2Error::Io(e.to_string())),
                },
            };
            crate::ws::set_sock_opts(&tcp);
            tls_h2_handshake(tcp, host, crate::tls::h2_client_config()).await
        })
    }
}

/// TLS-хендшейк с ALPN h2; ответ без h2 — ошибка (десктоп: «CF origin did
/// not negotiate h2»).
pub async fn tls_h2_handshake<S>(
    io: S,
    host: &str,
    cfg: Arc<rustls::ClientConfig>,
) -> Result<BoxIo, H2Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tls = tokio_rustls::TlsConnector::from(cfg)
        .connect(crate::ws::server_name(host), io)
        .await
        .map_err(|e| {
            crate::tls::report_handshake_error(&e, host, host);
            H2Error::Io(format!("TLS: {}", e))
        })?;
    if tls.get_ref().1.alpn_protocol() != Some(crate::tls::ALPN_H2) {
        return Err(H2Error::Protocol("CF origin did not negotiate h2".into()));
    }
    Ok(Box::new(tls))
}

struct Conn {
    send: h2::client::SendRequest<Bytes>,
    /// Отменяется при смерти соединения: задача-драйвер завершается и
    /// закрывает сокет, следующий запрос lane переподключается.
    dead: CancellationToken,
    /// Незавершённые запросы на этом соединении (для 3cda0f5).
    active: AtomicUsize,
}

impl Conn {
    fn fail(&self) {
        self.dead.cancel();
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.dead.cancel();
    }
}

struct ActiveGuard<'a>(&'a AtomicUsize);

impl<'a> ActiveGuard<'a> {
    fn new(c: &'a AtomicUsize) -> Self {
        c.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(c)
    }
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Lane (_HttpLane)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct LaneCap {
    inflight: usize,
    queued_bytes: usize,
    max_inflight: usize,
    reply_buffer_bytes: usize,
}

pub struct Lane {
    pub host: String,
    pub id: u64,
    limits: H2Limits,
    connector: Arc<dyn Connector>,
    cooldowns: Arc<Cooldowns>,
    pool: Weak<PoolInner>,
    conn: tokio::sync::Mutex<Option<Arc<Conn>>>,
    cap: Mutex<LaneCap>,
    cap_notify: Notify,
    channels: Mutex<Vec<(u64, Weak<Channel>)>>,
    idle_epoch: AtomicU64,
    closed: AtomicBool,
    closed_token: CancellationToken,
    pub tcp_connections: AtomicU64,
    pub requests: AtomicU64,
    pub responses: AtomicU64,
    pub errors: AtomicU64,
    pub replays: AtomicU64,
    pub capacity_rotations: AtomicU64,
}

/// Отметки о ходе запроса для канала (trace-события десктопа).
struct ReqHooks<'a> {
    channel: &'a Channel,
    id: u64,
}

impl Lane {
    fn new(
        host: String,
        id: u64,
        limits: H2Limits,
        connector: Arc<dyn Connector>,
        cooldowns: Arc<Cooldowns>,
        pool: Weak<PoolInner>,
    ) -> Arc<Lane> {
        Arc::new(Lane {
            host,
            id,
            limits,
            connector,
            cooldowns,
            pool,
            conn: tokio::sync::Mutex::new(None),
            cap: Mutex::new(LaneCap::default()),
            cap_notify: Notify::new(),
            channels: Mutex::new(Vec::new()),
            idle_epoch: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            closed_token: CancellationToken::new(),
            tcp_connections: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            responses: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            replays: AtomicU64::new(0),
            capacity_rotations: AtomicU64::new(0),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn channel_count(&self) -> usize {
        self.channels.lock().len()
    }

    pub fn inflight(&self) -> usize {
        self.cap.lock().inflight
    }

    pub fn queued_bytes(&self) -> usize {
        self.cap.lock().queued_bytes
    }

    pub fn max_inflight(&self) -> usize {
        self.cap.lock().max_inflight
    }

    pub fn reply_buffer_bytes(&self) -> usize {
        self.cap.lock().reply_buffer_bytes
    }

    pub fn in_cooldown(&self) -> bool {
        self.cooldowns.active(&self.host, Instant::now())
    }

    fn live_channels(&self) -> Vec<Arc<Channel>> {
        self.channels
            .lock()
            .iter()
            .filter_map(|(_, w)| w.upgrade())
            .collect()
    }

    fn add_channel(&self, id: u64, ch: &Arc<Channel>) -> bool {
        let mut list = self.channels.lock();
        if self.is_closed() {
            return false;
        }
        list.push((id, Arc::downgrade(ch)));
        self.idle_epoch.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn remove_channel(self: &Arc<Self>, id: u64) {
        let empty = {
            let mut list = self.channels.lock();
            list.retain(|(cid, w)| *cid != id && w.strong_count() > 0);
            list.is_empty()
        };
        if empty {
            self.schedule_idle_close();
        }
    }

    /// Lane без каналов закрывается через `lane_idle` (60 с): без клиентов
    /// модуль не держит соединений и таймеров.
    fn schedule_idle_close(self: &Arc<Self>) {
        if self.is_closed() || tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let epoch = self.idle_epoch.load(Ordering::Relaxed);
        let lane = Arc::downgrade(self);
        let closed = self.closed_token.clone();
        let idle = self.limits.lane_idle;
        tokio::spawn(async move {
            tokio::select! {
                _ = closed.cancelled() => return,
                _ = tokio::time::sleep(idle) => {}
            }
            let Some(lane) = lane.upgrade() else { return };
            if lane.idle_epoch.load(Ordering::Relaxed) != epoch || lane.channel_count() > 0 {
                return;
            }
            ldebug!("H2 lane={} host={} idle for {:?}, closing", lane.id, lane.host, idle);
            if let Some(pool) = lane.pool.upgrade() {
                pool.forget_lane(&lane);
            }
            lane.close().await;
        });
    }

    fn has_capacity(&self, cap: &LaneCap, len: usize) -> bool {
        cap.inflight < self.limits.lane_requests && cap.queued_bytes + len <= self.limits.lane_bytes
    }

    fn has_capacity_now(&self, len: usize) -> bool {
        let cap = self.cap.lock();
        self.has_capacity(&cap, len)
    }

    /// `_reserve`: место под запрос в lane. `wait == false` — для повторов:
    /// они никогда не ждут ёмкости.
    async fn reserve(&self, len: usize, wait: bool) -> Result<bool, H2Error> {
        let deadline = tokio::time::Instant::now() + self.limits.request_timeout;
        loop {
            let notified = self.cap_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut cap = self.cap.lock();
                let has = self.has_capacity(&cap, len);
                if !wait && !has {
                    return Ok(false);
                }
                if self.is_closed() {
                    return Err(H2Error::Closed("H2 lane closed"));
                }
                if has {
                    cap.inflight += 1;
                    cap.queued_bytes += len;
                    cap.max_inflight = cap.max_inflight.max(cap.inflight);
                    return Ok(true);
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(H2Error::Timeout("H2 lane capacity"));
            }
        }
    }

    fn release(&self, len: usize) {
        {
            let mut cap = self.cap.lock();
            cap.inflight = cap.inflight.saturating_sub(1);
            cap.queued_bytes = cap.queued_bytes.saturating_sub(len);
        }
        self.cap_notify.notify_waiters();
    }

    /// Живое соединение; мёртвое пересоздаётся (H2Transport.handle_async_request).
    async fn connection(&self) -> Result<Arc<Conn>, H2Error> {
        let mut slot = self.conn.lock().await;
        if self.is_closed() {
            return Err(H2Error::Closed("H2 transport closed"));
        }
        if let Some(c) = slot.as_ref() {
            if !c.dead.is_cancelled() {
                return Ok(c.clone());
            }
        }
        if let Some(old) = slot.take() {
            old.fail();
        }
        let n = self.tcp_connections.fetch_add(1, Ordering::Relaxed) + 1;
        STATS.h2_tcp_connections.fetch_add(1, Ordering::Relaxed);
        ldebug!(
            "H2 lane={} TCP_OPEN connection={} host={} channels={}",
            self.id,
            n,
            self.host,
            self.channel_count()
        );
        let setup = async {
            let io = self.connector.connect(&self.host).await?;
            let (send, connection) = h2::client::Builder::new()
                .initial_window_size(STREAM_RECEIVE_WINDOW)
                .initial_connection_window_size(CONNECTION_RECEIVE_WINDOW)
                .enable_push(false)
                .handshake::<_, Bytes>(io)
                .await?;
            Ok::<_, H2Error>((send, connection))
        };
        let (send, connection) = match tokio::time::timeout(self.limits.connect_timeout, setup).await
        {
            Ok(r) => r?,
            Err(_) => return Err(H2Error::Timeout("H2 TLS connect")),
        };
        let dead = CancellationToken::new();
        let conn = Arc::new(Conn {
            send,
            dead: dead.clone(),
            active: AtomicUsize::new(0),
        });
        let lane_id = self.id;
        let lane_closed = self.closed_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                r = connection => {
                    if let Err(e) = r {
                        ldebug!("H2 lane={} connection ended: {}", lane_id, e);
                    }
                }
                _ = dead.cancelled() => {}
                _ = lane_closed.cancelled() => {}
            }
            dead.cancel();
        });
        *slot = Some(conn.clone());
        Ok(conn)
    }

    /// Ожидание данных от сервера с таймаутом чтения. 3cda0f5: если по
    /// таймауту на соединении нет других активных запросов, соединение
    /// считается молча умершим и пересоздаётся следующим запросом.
    async fn read_wait<T>(
        &self,
        conn: &Conn,
        fut: impl Future<Output = T>,
    ) -> Result<T, H2Error> {
        tokio::select! {
            r = tokio::time::timeout(self.limits.request_timeout, fut) => match r {
                Ok(v) => Ok(v),
                Err(_) => {
                    if conn.active.load(Ordering::Relaxed) <= 1 {
                        ldebug!("H2 lane={} silent connection, reconnecting", self.id);
                        conn.fail();
                    }
                    Err(H2Error::Timeout("H2 stream read"))
                }
            },
            _ = conn.dead.cancelled() => Err(H2Error::Io("H2 connection lost".into())),
        }
    }

    fn request(&self, method: http::Method) -> http::Request<()> {
        http::Request::builder()
            .method(method)
            .uri(format!("https://{}/api", self.host))
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .header(http::header::ACCEPT_ENCODING, "identity")
            .body(())
            .expect("static request parts are valid")
    }

    async fn ready(&self, conn: &Conn) -> Result<h2::client::SendRequest<Bytes>, H2Error> {
        tokio::select! {
            r = tokio::time::timeout(self.limits.request_timeout, conn.send.clone().ready()) => match r {
                Ok(r) => Ok(r?),
                Err(_) => Err(H2Error::Timeout("H2 stream capacity")),
            },
            _ = conn.dead.cancelled() => Err(H2Error::Io("H2 connection lost".into())),
        }
    }

    /// `_preflight`: HEAD /api. Подходят 2xx, 405 и 501 (Telegram отвечает
    /// 501 на HEAD); HTTP/2 гарантирован ALPN.
    pub async fn preflight(&self) -> Result<u16, H2Error> {
        let started = Instant::now();
        let conn = self.connection().await?;
        let _active = ActiveGuard::new(&conn.active);
        let mut send = self.ready(&conn).await?;
        let (resp, _stream) = send.send_request(self.request(http::Method::HEAD), true)?;
        let resp = self.read_wait(&conn, resp).await??;
        let status = resp.status().as_u16();
        if !((200..300).contains(&status) || status == 405 || status == 501) {
            return Err(H2Error::Http(format!(
                "CF /api preflight HTTP {} cf_ray={}",
                status,
                header_str(resp.headers(), "cf-ray")
            )));
        }
        ldebug!(
            "H2 lane={} ready host={} status={} ms={}",
            self.id,
            self.host,
            status,
            started.elapsed().as_millis()
        );
        Ok(status)
    }

    /// `_post`: один пакет MTProto — один POST /api, ответ — один пакет.
    async fn post(&self, body: Bytes, hooks: Option<ReqHooks<'_>>, replay: bool) -> Result<Bytes, H2Error> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if replay {
            self.replays.fetch_add(1, Ordering::Relaxed);
        }
        STATS.h2_requests.fetch_add(1, Ordering::Relaxed);
        let result = self.post_inner(body, hooks).await;
        match &result {
            Ok(_) => {
                self.responses.fetch_add(1, Ordering::Relaxed);
                self.cooldowns.record_success(&self.host);
            }
            Err(H2Error::Transport(_)) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
            // Свой лимит памяти и закрытие lane (сброс, StopProxy) — не вина домена.
            Err(H2Error::ReplyBufferFull) | Err(H2Error::Closed(_)) => {}
            Err(_) if self.is_closed() => {}
            Err(_) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                self.cooldowns.record_failure(&self.host, Instant::now());
            }
        }
        result
    }

    async fn post_inner(&self, body: Bytes, hooks: Option<ReqHooks<'_>>) -> Result<Bytes, H2Error> {
        let conn = self.connection().await?;
        let _active = ActiveGuard::new(&conn.active);
        let mut send = self.ready(&conn).await?;
        let (resp, mut stream) = send.send_request(self.request(http::Method::POST), body.is_empty())?;
        self.send_body(&conn, &mut stream, body).await?;
        if let Some(h) = &hooks {
            h.channel.mark_sent(h.id);
        }
        let resp = self.read_wait(&conn, resp).await??;
        if let Some(h) = &hooks {
            h.channel.mark_receiving(h.id);
        }
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        if matches!(status, 403 | 404 | 429 | 444) {
            ldebug!(
                "H2 lane={} HTTP {} cf_ray={}",
                self.id,
                status,
                header_str(&headers, "cf-ray")
            );
            return Err(H2Error::Transport(-(status as i32)));
        }
        if status != 200 {
            return Err(H2Error::Http(format!(
                "CF /api HTTP {} cf_ray={}",
                status,
                header_str(&headers, "cf-ray")
            )));
        }
        if header_str(&headers, "content-type")
            .to_ascii_lowercase()
            .contains("text/html")
        {
            return Err(H2Error::Protocol("CF /api returned HTML instead of MTProto".into()));
        }
        let declared = match headers.get(http::header::CONTENT_LENGTH) {
            None => None,
            Some(v) => Some(
                v.to_str()
                    .ok()
                    .and_then(|s| s.trim().parse::<usize>().ok())
                    .ok_or_else(|| H2Error::Protocol("bad Content-Length".into()))?,
            ),
        };
        if declared.is_some_and(|d| d > self.limits.max_packet) {
            return Err(H2Error::Buffer(
                "H2 response Content-Length exceeds native packet bound".into(),
            ));
        }
        let mut recv = resp.into_body();
        let mut content = BytesMut::new();
        let mut budget = ReplyBudget { lane: self, held: 0 };
        loop {
            let chunk = match self.read_wait(&conn, recv.data()).await? {
                None => break,
                Some(r) => r?,
            };
            let n = chunk.len();
            let _ = recv.flow_control().release_capacity(n);
            if content.len() + n > self.limits.max_packet {
                return Err(H2Error::Buffer("H2 response exceeds native packet bound".into()));
            }
            budget.take(n)?;
            content.extend_from_slice(&chunk);
            if let Some(h) = &hooks {
                h.channel.mark_progress();
            }
        }
        let identity = header_str(&headers, "content-encoding")
            .eq_ignore_ascii_case("identity")
            || headers.get(http::header::CONTENT_ENCODING).is_none();
        if let Some(d) = declared {
            if identity && content.len() != d {
                return Err(H2Error::Protocol("incomplete H2 response body".into()));
            }
        }
        if content.len() & 3 != 0 {
            return Err(H2Error::Protocol(
                "CF /api response is not an aligned MTProto packet".into(),
            ));
        }
        if content.len() == 4 {
            let code = i32::from_le_bytes([content[0], content[1], content[2], content[3]]);
            if code < 0 {
                return Err(H2Error::Transport(code));
            }
        }
        Ok(content.freeze())
    }

    async fn send_body(
        &self,
        conn: &Conn,
        stream: &mut h2::SendStream<Bytes>,
        mut data: Bytes,
    ) -> Result<(), H2Error> {
        while !data.is_empty() {
            stream.reserve_capacity(data.len().min(IO_BATCH_SIZE));
            let cap = tokio::select! {
                r = tokio::time::timeout(
                    self.limits.request_timeout,
                    std::future::poll_fn(|cx| stream.poll_capacity(cx)),
                ) => match r {
                    Ok(Some(r)) => r?,
                    Ok(None) => return Err(H2Error::Protocol("H2 stream closed during upload".into())),
                    Err(_) => return Err(H2Error::Timeout("H2 upload flow control")),
                },
                _ = conn.dead.cancelled() => return Err(H2Error::Io("H2 connection lost".into())),
            };
            if cap == 0 {
                continue;
            }
            let chunk = data.split_to(cap.min(data.len()));
            stream.send_data(chunk, data.is_empty())?;
        }
        Ok(())
    }

    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.closed_token.cancel();
        self.cap_notify.notify_waiters();
        let channels = self.live_channels();
        futures_join_all(channels.iter().map(|c| c.close())).await;
        if let Some(conn) = self.conn.lock().await.take() {
            conn.fail();
        }
        ldebug!(
            "H2 CLOSED lane={} host={} tcp_connections={} requests={} replies={} errors={} replays={} capacity_rotations={}",
            self.id,
            self.host,
            self.tcp_connections.load(Ordering::Relaxed),
            self.requests.load(Ordering::Relaxed),
            self.responses.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.replays.load(Ordering::Relaxed),
            self.capacity_rotations.load(Ordering::Relaxed),
        );
    }
}

/// Учёт буферов ответов в бюджете lane; возвращается при любом выходе.
struct ReplyBudget<'a> {
    lane: &'a Lane,
    held: usize,
}

impl ReplyBudget<'_> {
    fn take(&mut self, n: usize) -> Result<(), H2Error> {
        let mut cap = self.lane.cap.lock();
        if cap.reply_buffer_bytes + n > self.lane.limits.lane_reply_bytes {
            return Err(H2Error::ReplyBufferFull);
        }
        cap.reply_buffer_bytes += n;
        self.held += n;
        Ok(())
    }
}

impl Drop for ReplyBudget<'_> {
    fn drop(&mut self) {
        if self.held > 0 {
            let mut cap = self.lane.cap.lock();
            cap.reply_buffer_bytes = cap.reply_buffer_bytes.saturating_sub(self.held);
        }
    }
}

fn header_str<'a>(headers: &'a http::HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
}

async fn futures_join_all<F: Future<Output = ()>>(futs: impl Iterator<Item = F>) {
    let mut set = Vec::new();
    for f in futs {
        set.push(Box::pin(f));
    }
    for f in set {
        f.await;
    }
}

// ---------------------------------------------------------------------------
// Channel (_HttpChannel)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UploadPhase {
    SendLock,
    ChannelCapacity,
    LaneCapacity,
}

struct Req {
    len: usize,
    /// sent_since: тело отдано соединению. Снимается при «выводе» запроса
    /// ради места (capacity rotation).
    sent: Option<Instant>,
    receiving: bool,
    abort: Option<AbortHandle>,
    done: CancellationToken,
}

struct ReplayPacket {
    sent_at: Instant,
    body: Bytes,
    sequence: u64,
    attempts: u32,
    last_attempt: Option<Instant>,
    pending: Option<u64>,
    originals: HashSet<u64>,
    retired: bool,
    reply_id: Option<Bytes>,
}

impl ReplayPacket {
    fn replayed(&self) -> bool {
        self.last_attempt.is_some() || self.attempts > 0
    }
}

struct ChState {
    closed: bool,
    transport_error: Option<i32>,
    failure: Option<H2Error>,
    /// Порядок ключей = порядок создания (как dict pending в Python).
    reqs: BTreeMap<u64, Req>,
    pending_bytes: usize,
    replay_pending: HashSet<u64>,
    queue: std::collections::VecDeque<Bytes>,
    reply_bytes: usize,
    delivering: bool,
    history: Vec<ReplayPacket>,
    replay_key: Option<[u8; 8]>,
    upload_wait: Option<(UploadPhase, usize)>,
    next_req: u64,
    last_progress: Instant,
    requests: u64,
    replay_requests: u64,
    quick_requests: u64,
    up: u64,
    down: u64,
    capacity_rotations: u64,
    replay_rotations: u64,
    /// Проходы задачи повторов (проверка, что без дела она спит).
    recovery_passes: u64,
}

pub struct Channel {
    pub id: u64,
    pub label: String,
    lane: Arc<Lane>,
    st: Mutex<ChState>,
    capacity: Notify,
    recv_notify: Notify,
    recovery: Notify,
    send_lock: tokio::sync::Mutex<()>,
    close_lock: tokio::sync::Mutex<bool>,
    started: Instant,
}

/// Снимок для тестов и логов.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChannelStats {
    pub pending: usize,
    pub pending_bytes: usize,
    pub replay_pending: usize,
    pub receiving: usize,
    pub requests: u64,
    pub replay_requests: u64,
    pub capacity_rotations: u64,
    pub replay_rotations: u64,
    pub recovery_passes: u64,
    pub history: usize,
    pub closed: bool,
}

/// Снимает запрос с учёта при любом завершении задачи, включая отмену до
/// первого опроса (десктоп: _finish_request в finally).
struct ReqGuard {
    ch: Arc<Channel>,
    id: u64,
}

impl Drop for ReqGuard {
    fn drop(&mut self) {
        self.ch.finish_request(self.id);
    }
}

struct UploadWaitGuard<'a>(&'a Channel);

impl Drop for UploadWaitGuard<'_> {
    fn drop(&mut self) {
        self.0.st.lock().upload_wait = None;
        // send_lock освобождается: отложенный повтор может пройти.
        self.0.wake_recovery();
    }
}

enum Pick {
    Send(Bytes),
    Replace(Bytes, u64),
}

impl Channel {
    fn new(lane: Arc<Lane>, id: u64, label: &str) -> Option<Arc<Channel>> {
        let now = Instant::now();
        let ch = Arc::new(Channel {
            id,
            label: label.to_string(),
            lane: lane.clone(),
            st: Mutex::new(ChState {
                closed: false,
                transport_error: None,
                failure: None,
                reqs: BTreeMap::new(),
                pending_bytes: 0,
                replay_pending: HashSet::new(),
                queue: std::collections::VecDeque::new(),
                reply_bytes: 0,
                delivering: false,
                history: Vec::new(),
                replay_key: None,
                upload_wait: None,
                next_req: 1,
                last_progress: now,
                requests: 0,
                replay_requests: 0,
                quick_requests: 0,
                up: 0,
                down: 0,
                capacity_rotations: 0,
                replay_rotations: 0,
                recovery_passes: 0,
            }),
            capacity: Notify::new(),
            recv_notify: Notify::new(),
            recovery: Notify::new(),
            send_lock: tokio::sync::Mutex::new(()),
            close_lock: tokio::sync::Mutex::new(false),
            started: now,
        });
        if lane.add_channel(id, &ch) {
            Some(ch)
        } else {
            None
        }
    }

    pub fn lane(&self) -> &Arc<Lane> {
        &self.lane
    }

    pub fn is_closed(&self) -> bool {
        self.st.lock().closed
    }

    pub fn transport_error(&self) -> Option<i32> {
        self.st.lock().transport_error
    }

    pub fn stats(&self) -> ChannelStats {
        let st = self.st.lock();
        ChannelStats {
            pending: st.reqs.len(),
            pending_bytes: st.pending_bytes,
            replay_pending: st.replay_pending.len(),
            receiving: st.reqs.values().filter(|r| r.receiving).count(),
            requests: st.requests,
            replay_requests: st.replay_requests,
            capacity_rotations: st.capacity_rotations,
            replay_rotations: st.replay_rotations,
            recovery_passes: st.recovery_passes,
            history: st.history.len(),
            closed: st.closed,
        }
    }

    fn limits(&self) -> &H2Limits {
        &self.lane.limits
    }

    fn has_capacity(&self, st: &ChState, len: usize) -> bool {
        st.reqs.len() < self.limits().channel_requests
            && st.pending_bytes + len <= self.limits().channel_bytes
    }

    fn native_backpressure(st: &ChState) -> bool {
        st.reply_bytes > 0 || st.delivering
    }

    fn wake_recovery(&self) {
        self.recovery.notify_one();
    }

    fn mark_sent(&self, id: u64) {
        let mut st = self.st.lock();
        if let Some(r) = st.reqs.get_mut(&id) {
            r.sent = Some(Instant::now());
        }
        drop(st);
        self.wake_recovery();
    }

    fn mark_receiving(&self, id: u64) {
        let mut st = self.st.lock();
        st.last_progress = Instant::now();
        if let Some(r) = st.reqs.get_mut(&id) {
            r.receiving = true;
        }
    }

    fn mark_progress(&self) {
        self.st.lock().last_progress = Instant::now();
    }

    /// `_fail`: закрыть канал с ошибкой, которую получит receive().
    fn fail_locked(&self, st: &mut ChState, err: H2Error) {
        if st.closed {
            return;
        }
        if let H2Error::Transport(code) = err {
            st.transport_error = Some(code);
        }
        st.closed = true;
        st.queue.clear();
        st.reply_bytes = 0;
        st.failure = Some(err);
        self.recv_notify.notify_one();
        self.recovery.notify_one();
        self.capacity.notify_waiters();
    }

    // ----- правила повторов (порт 1-в-1, кроме опроса) -----

    fn overdue_original(st: &ChState, e: &ReplayPacket, now: Instant, t: &H2ReplayTiming) -> bool {
        e.retired
            || e.originals.iter().any(|id| {
                st.reqs.get(id).is_some_and(|r| {
                    !r.receiving && r.sent.is_some_and(|s| now.duration_since(s) >= t.request)
                })
            })
    }

    fn replay_limit(st: &ChState, idx: usize) -> u32 {
        let e = &st.history[idx];
        if !e.originals.is_empty() || e.retired || idx + 1 == st.history.len() {
            REPLAY_MAX_ATTEMPTS
        } else {
            0
        }
    }

    fn replay_blocker(
        st: &ChState,
        idx: usize,
        now: Instant,
        t: &H2ReplayTiming,
    ) -> Option<&'static str> {
        let e = &st.history[idx];
        if now.saturating_duration_since(e.sent_at) > t.max_age {
            return Some("expired");
        }
        if e.attempts >= Self::replay_limit(st, idx) {
            return Some("budget-used");
        }
        if Self::native_backpressure(st) {
            return Some("native-backpressure");
        }
        if e
            .originals
            .iter()
            .any(|id| st.reqs.get(id).is_some_and(|r| r.receiving))
        {
            return Some("original-body");
        }
        if e
            .pending
            .is_some_and(|id| st.reqs.get(&id).is_some_and(|r| r.receiving))
        {
            return Some("replay-body");
        }
        if e.replayed()
            && e
                .last_attempt
                .is_some_and(|a| now.saturating_duration_since(a) < t.retry)
        {
            return Some("backoff-or-progress");
        }
        if Self::overdue_original(st, e, now, t) {
            return None;
        }
        if idx + 1 != st.history.len() || st.reqs.keys().any(|id| Some(*id) != e.pending) {
            return Some("receiver-active");
        }
        if e.replayed() && now.saturating_duration_since(st.last_progress) < t.idle {
            return Some("backoff-or-progress");
        }
        None
    }

    fn find_packet(st: &ChState, body: &[u8]) -> Option<usize> {
        st.history.iter().position(|e| e.body[..] == *body)
    }

    fn remember_packet(st: &mut ChState, body: &Bytes, now: Instant) -> Option<usize> {
        if body.len() < 8 {
            return None;
        }
        let mut key = [0u8; 8];
        key.copy_from_slice(&body[..8]);
        // Незашифрованные пакеты (auth_key_id == 0) не повторяются.
        if key == [0u8; 8] {
            return None;
        }
        if st.replay_key != Some(key) {
            st.history.clear();
            st.replay_key = Some(key);
        }
        if body.len() > REPLAY_HISTORY_BYTES {
            return None;
        }
        if let Some(idx) = Self::find_packet(st, body) {
            return Some(idx);
        }
        st.history.push(ReplayPacket {
            sent_at: now,
            body: body.clone(),
            sequence: st.requests,
            attempts: 0,
            last_attempt: None,
            pending: None,
            originals: HashSet::new(),
            retired: false,
            reply_id: None,
        });
        Some(st.history.len() - 1)
    }

    fn trim_history(st: &mut ChState, now: Instant, t: &H2ReplayTiming) {
        let mut retained: usize = st.history.iter().map(|e| e.body.len()).sum();
        while st.history.len() > REPLAY_HISTORY_PACKETS || retained > REPLAY_HISTORY_BYTES {
            let victim = st
                .history
                .iter()
                .position(|e| {
                    e.originals.is_empty()
                        && !(e.retired
                            && e.attempts < REPLAY_MAX_ATTEMPTS
                            && now.saturating_duration_since(e.sent_at) <= t.max_age)
                })
                .unwrap_or(0);
            retained -= st.history.remove(victim).body.len();
        }
    }

    /// `_capacity_candidate`: запрос, отправленный давно, без начатого тела
    /// ответа: повтор или оригинал, пакет которого есть в истории.
    fn capacity_candidate(st: &ChState, now: Instant, t: &H2ReplayTiming) -> Option<(u64, Option<usize>)> {
        let mut sent: Vec<(bool, Instant, u64)> = st
            .reqs
            .iter()
            .filter_map(|(id, r)| r.sent.map(|s| (!st.replay_pending.contains(id), s, *id)))
            .collect();
        sent.sort();
        for (_, s, id) in sent {
            let r = &st.reqs[&id];
            if r.receiving || now.saturating_duration_since(s) < t.request {
                continue;
            }
            if st.replay_pending.contains(&id) {
                return Some((id, None));
            }
            if let Some(idx) = st.history.iter().position(|e| e.originals.contains(&id)) {
                if now.saturating_duration_since(st.history[idx].sent_at) <= t.max_age {
                    return Some((id, Some(idx)));
                }
            }
        }
        None
    }

    fn min_sent(&self) -> Option<Instant> {
        self.st.lock().reqs.values().filter_map(|r| r.sent).min()
    }

    /// `_make_upload_room`: клиентский пакет ждёт места в канале или lane,
    /// а место заняли долгие опросы. Самый старый подходящий запрос
    /// отменяется; его пакет помечается retired и будет повторён.
    async fn make_upload_room(self: &Arc<Self>, now: Instant, t: &H2ReplayTiming) {
        let (phase, bytes) = {
            let st = self.st.lock();
            if st.closed {
                return;
            }
            match st.upload_wait {
                Some(w) => w,
                None => return,
            }
        };
        let channels: Vec<Arc<Channel>> = match phase {
            UploadPhase::ChannelCapacity => {
                let st = self.st.lock();
                if self.has_capacity(&st, bytes) {
                    return;
                }
                vec![self.clone()]
            }
            UploadPhase::LaneCapacity => {
                if self.lane.has_capacity_now(bytes) {
                    return;
                }
                let mut list: Vec<(Instant, Arc<Channel>)> = self
                    .lane
                    .live_channels()
                    .into_iter()
                    .map(|c| (c.min_sent().unwrap_or(now), c))
                    .collect();
                list.sort_by_key(|(s, _)| *s);
                list.into_iter().map(|(_, c)| c).collect()
            }
            UploadPhase::SendLock => return,
        };
        for channel in channels {
            let victim = {
                let mut st = channel.st.lock();
                let Some((id, entry)) = Self::capacity_candidate(&st, now, t) else {
                    continue;
                };
                if let Some(r) = st.reqs.get_mut(&id) {
                    r.sent = None;
                }
                if let Some(idx) = entry {
                    st.history[idx].retired = true;
                }
                st.capacity_rotations += 1;
                st.reqs.get(&id).map(|r| (r.abort.clone(), r.done.clone()))
            };
            self.lane.capacity_rotations.fetch_add(1, Ordering::Relaxed);
            ldebug!(
                "H2 CAPACITY lane={} waiting_channel={} release_channel={} reason={:?}",
                self.lane.id,
                self.id,
                channel.id,
                phase
            );
            if let Some((abort, done)) = victim {
                cancel_request(abort, done).await;
            }
            return;
        }
    }

    /// Ближайший момент, когда решение о повторе или освобождении места
    /// может измениться. Вместо опроса раз в 0,25 с.
    fn next_deadline(&self, now: Instant, t: &H2ReplayTiming) -> Option<Instant> {
        let mut times: Vec<Instant> = Vec::new();
        let lane_wait = {
            let st = self.st.lock();
            if st.closed {
                return None;
            }
            for e in &st.history {
                if let Some(a) = e.last_attempt {
                    times.push(a + t.retry);
                }
            }
            if !st.history.is_empty() {
                times.push(st.last_progress + t.idle);
            }
            for r in st.reqs.values() {
                if let Some(s) = r.sent {
                    times.push(s + t.request);
                    times.push(s + t.slot);
                }
            }
            matches!(st.upload_wait, Some((UploadPhase::LaneCapacity, _)))
        };
        if lane_wait {
            for c in self.lane.live_channels() {
                if c.id == self.id {
                    continue;
                }
                let st = c.st.lock();
                for r in st.reqs.values() {
                    if let Some(s) = r.sent {
                        times.push(s + t.request);
                    }
                }
            }
        }
        times.into_iter().filter(|d| *d > now).min()
    }

    fn pick_replay(st: &ChState, now: Instant, t: &H2ReplayTiming) -> Option<Pick> {
        let mut order: Vec<(bool, i128, usize)> = st
            .history
            .iter()
            .enumerate()
            .map(|(idx, e)| {
                let overdue = Self::overdue_original(st, e, now, t);
                let seq = e.sequence as i128;
                (!overdue, if overdue { seq } else { -seq }, idx)
            })
            .collect();
        order.sort();
        for (_, _, idx) in order {
            if Self::replay_blocker(st, idx, now, t).is_some() {
                continue;
            }
            let e = &st.history[idx];
            let mut replace = e.pending;
            if replace.is_none() && st.replay_pending.len() >= MAX_CHANNEL_REPLAYS {
                replace = st
                    .reqs
                    .iter()
                    .find(|(id, r)| st.replay_pending.contains(id) && !r.receiving)
                    .map(|(id, _)| *id);
                if replace.is_none() {
                    continue;
                }
            }
            if let Some(rid) = replace {
                let Some(r) = st.reqs.get(&rid) else { continue };
                let slot_held = r
                    .sent
                    .map(|s| now.saturating_duration_since(s) >= t.slot)
                    .unwrap_or(false);
                if r.receiving || !slot_held {
                    continue;
                }
                return Some(Pick::Replace(e.body.clone(), rid));
            }
            return Some(Pick::Send(e.body.clone()));
        }
        None
    }

    /// `_recover`: повторы последнего пакета (роль длинного опроса: по HTTP
    /// сервер отвечает только на запрос) и освобождение места.
    pub async fn recover(self: Arc<Self>) -> Result<(), H2Error> {
        loop {
            let t = self.limits().timing();
            let now = Instant::now();
            self.make_upload_room(now, &t).await;
            let pick = {
                let mut st = self.st.lock();
                if st.closed {
                    return Ok(());
                }
                st.recovery_passes += 1;
                if Self::native_backpressure(&st) {
                    None
                } else {
                    Self::pick_replay(&st, now, &t)
                }
            };
            let picked = pick.is_some();
            let sent = match pick {
                Some(Pick::Send(body)) => self.send(body, false, true).await?,
                Some(Pick::Replace(body, rid)) => {
                    let victim = {
                        let st = self.st.lock();
                        st.reqs.get(&rid).map(|r| (r.abort.clone(), r.done.clone()))
                    };
                    if let Some((abort, done)) = victim {
                        cancel_request(abort, done).await;
                        self.st.lock().replay_rotations += 1;
                    }
                    self.send(body, false, true).await?
                }
                None => false,
            };
            let now = Instant::now();
            let mut deadline = self.next_deadline(now, &t);
            if picked && !sent {
                // Повтор пора отправить, но нет места в канале или lane:
                // освобождение места в другом канале нас не будит, поэтому
                // короткий таймер — только пока такой кандидат есть.
                let retry = now + BLOCKED_REPLAY_RETRY;
                deadline = Some(deadline.map_or(retry, |d| d.min(retry)));
            }
            match deadline {
                Some(d) => {
                    tokio::select! {
                        _ = self.recovery.notified() => {}
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(d)) => {}
                    }
                }
                None => self.recovery.notified().await,
            }
        }
    }

    /// `send`: отправить пакет. Клиентские пакеты ждут места; повторы
    /// (`replay`) не ждут ничего и возвращают false, если сейчас нельзя.
    pub async fn send(self: &Arc<Self>, body: Bytes, quick: bool, replay: bool) -> Result<bool, H2Error> {
        let len = body.len();
        let _wait_guard;
        let _lock = if replay {
            match self.send_lock.try_lock() {
                Ok(g) => g,
                Err(_) => return Ok(false),
            }
        } else {
            self.st.lock().upload_wait = Some((UploadPhase::SendLock, len));
            _wait_guard = UploadWaitGuard(self);
            self.send_lock.lock().await
        };
        if replay {
            let st = self.st.lock();
            if !self.has_capacity(&st, len) {
                return Ok(false);
            }
        } else {
            self.st.lock().upload_wait = Some((UploadPhase::ChannelCapacity, len));
            self.wake_recovery();
            let deadline = tokio::time::Instant::now() + self.limits().request_timeout;
            loop {
                let notified = self.capacity.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let st = self.st.lock();
                    if st.closed || self.has_capacity(&st, len) {
                        break;
                    }
                }
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    return Err(H2Error::Timeout("H2 channel capacity"));
                }
            }
        }
        if self.is_closed() {
            return Err(H2Error::Closed("H2 channel closed"));
        }
        if !replay {
            self.st.lock().upload_wait = Some((UploadPhase::LaneCapacity, len));
            self.wake_recovery();
        }
        if !self.lane.reserve(len, !replay).await? {
            return Ok(false);
        }
        let t = self.limits().timing();
        let id = {
            let mut st = self.st.lock();
            if st.closed {
                drop(st);
                self.lane.release(len);
                return Err(H2Error::Closed("H2 channel closed"));
            }
            let now = Instant::now();
            let replay_idx = if replay { Self::find_packet(&st, &body) } else { None };
            if replay {
                let ok = replay_idx.is_some_and(|idx| {
                    st.history[idx].pending.is_none()
                        && Self::replay_blocker(&st, idx, now, &t).is_none()
                });
                if !ok {
                    drop(st);
                    self.lane.release(len);
                    return Ok(false);
                }
            }
            st.pending_bytes += len;
            st.requests += 1;
            if replay {
                st.replay_requests += 1;
            }
            st.up += len as u64;
            if quick {
                st.quick_requests += 1;
            }
            STATS.bytes_up.fetch_add(len as i64, Ordering::Relaxed);
            let id = st.next_req;
            st.next_req += 1;
            st.reqs.insert(
                id,
                Req {
                    len,
                    sent: None,
                    receiving: false,
                    abort: None,
                    done: CancellationToken::new(),
                },
            );
            if replay {
                let idx = replay_idx.expect("checked above");
                st.replay_pending.insert(id);
                let e = &mut st.history[idx];
                e.attempts += 1;
                e.last_attempt = Some(now);
                e.pending = Some(id);
            } else if let Some(idx) = Self::remember_packet(&mut st, &body, now) {
                st.history[idx].originals.insert(id);
                Self::trim_history(&mut st, now, &t);
            }
            id
        };
        let guard = ReqGuard {
            ch: self.clone(),
            id,
        };
        let ch = self.clone();
        let handle = tokio::spawn(async move {
            let _guard = guard;
            let result = ch
                .lane
                .post(body.clone(), Some(ReqHooks { channel: &ch, id }), replay)
                .await;
            ch.on_result(id, &body, replay, result);
        });
        {
            let mut st = self.st.lock();
            if let Some(r) = st.reqs.get_mut(&id) {
                r.abort = Some(handle.abort_handle());
            }
        }
        Ok(true)
    }

    fn on_result(&self, id: u64, body: &Bytes, replay: bool, result: Result<Bytes, H2Error>) {
        let mut st = self.st.lock();
        st.last_progress = Instant::now();
        if let Some(r) = st.reqs.get_mut(&id) {
            r.receiving = false;
        }
        match result {
            Ok(reply) => {
                if reply.is_empty() || st.closed {
                    return;
                }
                let rid = reply.slice(..reply.len().min(24));
                if let Some(e) = st
                    .history
                    .iter_mut()
                    .find(|e| e.originals.contains(&id) || e.pending == Some(id))
                {
                    if e.reply_id.as_ref() != Some(&rid) {
                        e.reply_id = Some(rid);
                        e.attempts = 0;
                    }
                }
                if st.queue.len() >= REPLY_QUEUE
                    || st.reply_bytes + reply.len() > self.limits().channel_bytes
                {
                    STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                    lwarn!(
                        "[{}] H2 lane={} channel={} client response queue exceeded bound",
                        self.label,
                        self.lane.id,
                        self.id
                    );
                    self.fail_locked(
                        &mut st,
                        H2Error::Buffer("H2 client response queue exceeded bound".into()),
                    );
                    return;
                }
                st.reply_bytes += reply.len();
                st.queue.push_back(reply);
                self.recv_notify.notify_one();
            }
            Err(e) => {
                STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                if !st.closed {
                    if let H2Error::Transport(code) = e {
                        lwarn!(
                            "[{}] H2 lane={} channel={} host={} MTProto transport error={} encrypted={} bytes={} replay={}; reporting to client",
                            self.label,
                            self.lane.id,
                            self.id,
                            self.lane.host,
                            code,
                            body.len() >= 8 && body[..8] != [0u8; 8],
                            body.len(),
                            replay
                        );
                    } else {
                        lwarn!(
                            "[{}] H2 lane={} channel={} request failed: {}; closing native channel",
                            self.label,
                            self.lane.id,
                            self.id,
                            e
                        );
                    }
                }
                self.fail_locked(&mut st, e);
            }
        }
    }

    /// `_finish_request`.
    fn finish_request(&self, id: u64) {
        let len = {
            let mut st = self.st.lock();
            let Some(req) = st.reqs.remove(&id) else {
                return;
            };
            st.pending_bytes = st.pending_bytes.saturating_sub(req.len);
            st.replay_pending.remove(&id);
            for e in st.history.iter_mut() {
                e.originals.remove(&id);
                if e.pending == Some(id) {
                    e.pending = None;
                }
            }
            req.done.cancel();
            req.len
        };
        self.lane.release(len);
        self.capacity.notify_waiters();
        self.capacity.notify_one();
        self.wake_recovery();
    }

    /// `receive`: следующий ответ для клиента или ошибка закрытого канала.
    pub async fn receive(&self) -> Result<Bytes, H2Error> {
        loop {
            {
                let mut st = self.st.lock();
                if let Some(b) = st.queue.pop_front() {
                    st.reply_bytes = st.reply_bytes.saturating_sub(b.len());
                    drop(st);
                    self.wake_recovery();
                    return Ok(b);
                }
                if let Some(e) = &st.failure {
                    return Err(e.clone());
                }
            }
            self.recv_notify.notified().await;
        }
    }

    fn set_delivering(&self, v: bool) {
        self.st.lock().delivering = v;
        if !v {
            self.wake_recovery();
        }
    }

    fn delivered(&self, n: usize) {
        let mut st = self.st.lock();
        st.down += n as u64;
        st.last_progress = Instant::now();
        drop(st);
        STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
        self.wake_recovery();
    }

    /// `close`: отменить запросы канала, освободить место в lane. Повторный
    /// вызов ждёт первый и ничего не делает.
    pub async fn close(self: &Arc<Self>) {
        let mut done_flag = self.close_lock.lock().await;
        if *done_flag {
            return;
        }
        let victims: Vec<(Option<AbortHandle>, CancellationToken)> = {
            let mut st = self.st.lock();
            self.fail_locked(&mut st, H2Error::Closed("H2 channel closed"));
            st.reqs
                .values()
                .map(|r| (r.abort.clone(), r.done.clone()))
                .collect()
        };
        for (abort, done) in victims {
            cancel_request(abort, done).await;
        }
        let stats = {
            let mut st = self.st.lock();
            st.replay_pending.clear();
            st.history.clear();
            (st.requests, st.replay_requests, st.replay_rotations, st.capacity_rotations, st.up, st.down, st.quick_requests)
        };
        self.lane.remove_channel(self.id);
        *done_flag = true;
        ldebug!(
            "[{}] H2 channel={} closed lane={} requests={} replays={} rotations={} capacity_rotations={} up={} down={} quickack={} duration={:.1}s remaining_channels={}",
            self.label,
            self.id,
            self.lane.id,
            stats.0,
            stats.1,
            stats.2,
            stats.3,
            stats.4,
            stats.5,
            stats.6,
            self.started.elapsed().as_secs_f64(),
            self.lane.channel_count()
        );
    }

    pub fn close_done(&self) -> bool {
        self.close_lock.try_lock().map(|g| *g).unwrap_or(false)
    }
}

/// Отмена задачи запроса с ожиданием её завершения (asyncio: cancel + gather).
async fn cancel_request(abort: Option<AbortHandle>, done: CancellationToken) {
    if let Some(a) = abort {
        a.abort();
    }
    // Задача без AbortHandle ещё регистрируется в send(): её не отменить,
    // ждём штатного завершения. Таймаут — страховка от зависания close.
    let _ = tokio::time::timeout(Duration::from_secs(5), done.cancelled()).await;
}

// ---------------------------------------------------------------------------
// bridge_h2
// ---------------------------------------------------------------------------

enum BridgeEnd {
    NativeEof,
    Native(String),
    Channel(H2Error),
    Cancelled,
}

/// Порт `bridge_h2`: upload (пакеты клиента → POST), download (ответы →
/// клиенту), recover (повторы). Первая завершившаяся задача завершает мост.
/// При транспортной ошибке клиент получает её код в своей рамке.
#[allow(clippy::too_many_arguments)]
pub async fn bridge_h2<R, W>(
    mut reader: R,
    mut writer: W,
    channel: Arc<Channel>,
    mut clt_dec: TrackedStream,
    mut clt_enc: TrackedStream,
    proto: u32,
    cancel: CancellationToken,
) where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let proto_type = proto_tag_to_type(proto);
    let max_packet = channel.limits().max_packet;
    let end = {
        let upload = async {
            loop {
                let (body, quick) =
                    match read_packet(&mut reader, &mut clt_dec, proto_type, max_packet).await {
                        Ok(p) => p,
                        Err(PacketError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            return BridgeEnd::NativeEof
                        }
                        Err(PacketError::Io(e)) => return BridgeEnd::Native(e.to_string()),
                        Err(PacketError::Invalid(s)) => {
                            return BridgeEnd::Channel(H2Error::Protocol(s))
                        }
                    };
                if let Err(e) = channel.send(Bytes::from(body), quick, false).await {
                    return BridgeEnd::Channel(e);
                }
            }
        };
        let download = async {
            loop {
                let body = match channel.receive().await {
                    Ok(b) => b,
                    Err(e) => return BridgeEnd::Channel(e),
                };
                if channel.is_closed() {
                    return BridgeEnd::Native("H2 channel closed before native response".into());
                }
                let mut frame = match encode_reply(&body, proto_type, max_packet) {
                    Ok(f) => f,
                    Err(s) => return BridgeEnd::Channel(H2Error::Protocol(s)),
                };
                clt_enc.xor(&mut frame);
                channel.set_delivering(true);
                let res = async {
                    writer.write_all(&frame).await?;
                    writer.flush().await
                }
                .await;
                channel.set_delivering(false);
                if let Err(e) = res {
                    return BridgeEnd::Native(e.to_string());
                }
                channel.delivered(body.len());
            }
        };
        let recover = channel.clone().recover();
        tokio::select! {
            e = upload => e,
            e = download => e,
            r = recover => match r {
                Ok(()) => BridgeEnd::Channel(H2Error::Closed("H2 channel closed")),
                Err(e) => BridgeEnd::Channel(e),
            },
            _ = cancel.cancelled() => BridgeEnd::Cancelled,
        }
    };
    if let Some(code) = channel.transport_error() {
        if let Ok(mut frame) = encode_reply(&code.to_le_bytes(), proto_type, max_packet) {
            clt_enc.xor(&mut frame);
            if writer.write_all(&frame).await.is_ok() {
                let _ = writer.flush().await;
                channel.delivered(4);
            }
        }
    } else {
        match end {
            BridgeEnd::NativeEof => ldebug!("[{}] H2 channel={} native EOF", channel.label, channel.id),
            BridgeEnd::Native(s) => {
                ldebug!("[{}] H2 channel={} native closed: {}", channel.label, channel.id, s)
            }
            BridgeEnd::Channel(e) => {
                if !matches!(e, H2Error::Closed(_)) {
                    lwarn!("[{}] H2 channel={} bridge ended: {}", channel.label, channel.id, e);
                }
            }
            BridgeEnd::Cancelled => {}
        }
    }
    let _ = writer.shutdown().await;
    channel.close().await;
}

// ---------------------------------------------------------------------------
// H2Pool (CfH2Pool)
// ---------------------------------------------------------------------------

struct PoolInner {
    connector: Arc<dyn Connector>,
    limits: H2Limits,
    lanes: Mutex<HashMap<String, Arc<Lane>>>,
    host_cooldowns: Arc<Cooldowns>,
    dc_cooldowns: Cooldowns,
    setups: Mutex<HashMap<i32, u64>>,
    closed: AtomicBool,
    epoch: Mutex<CancellationToken>,
    generation: AtomicU64,
    next_lane: AtomicU64,
    next_channel: AtomicU64,
}

impl PoolInner {
    fn forget_lane(&self, lane: &Arc<Lane>) {
        let mut lanes = self.lanes.lock();
        if lanes.get(&lane.host).is_some_and(|l| Arc::ptr_eq(l, lane)) {
            lanes.remove(&lane.host);
        }
    }

    fn new_lane(self: &Arc<Self>, host: String) -> Arc<Lane> {
        Lane::new(
            host,
            self.next_lane.fetch_add(1, Ordering::Relaxed) + 1,
            self.limits.clone(),
            self.connector.clone(),
            self.host_cooldowns.clone(),
            Arc::downgrade(self),
        )
    }

    /// Фоновая подготовка lane для DC: перебор доменов балансера, первый
    /// прошедший preflight сохраняется.
    async fn setup(self: &Arc<Self>, dc: i32, domains: Vec<String>, generation: u64) -> bool {
        for base in domains {
            // v1.12.0: TLS к этому CF-домену недавно завис — H2 не пробуем.
            if crate::cf_websocket::cf_tls_in_cooldown(&base) {
                continue;
            }
            let host = format!("kws{}.{}", dc, base);
            if self.host_cooldowns.active(&host, Instant::now()) {
                continue;
            }
            if self.lanes.lock().get(&host).is_some_and(|l| !l.is_closed()) {
                return true;
            }
            let lane = self.new_lane(host.clone());
            match lane.preflight().await {
                Ok(_) => {
                    let stale = self.closed.load(Ordering::Acquire)
                        || self.generation.load(Ordering::Acquire) != generation;
                    if stale {
                        lane.close().await;
                        return false;
                    }
                    self.host_cooldowns.record_success(&host);
                    let old = self.lanes.lock().insert(host.clone(), lane.clone());
                    if let Some(old) = old {
                        tokio::spawn(async move { old.close().await });
                    }
                    lane.schedule_idle_close();
                    linfo!("H2 lane={} ready for DC{} host={}", lane.id, dc, host);
                    return true;
                }
                Err(e) => {
                    STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                    let cd = self.host_cooldowns.record_failure(&host, Instant::now());
                    lwarn!(
                        "H2 lane={} preflight failed host={}: {}; cooldown {}s",
                        lane.id,
                        host,
                        e,
                        cd.as_secs()
                    );
                    lane.close().await;
                }
            }
        }
        false
    }
}

pub struct H2Pool {
    inner: Arc<PoolInner>,
}

impl H2Pool {
    pub fn new() -> Self {
        Self::with_connector(Arc::new(CfTlsConnector), H2Limits::default())
    }

    pub fn with_connector(connector: Arc<dyn Connector>, limits: H2Limits) -> Self {
        H2Pool {
            inner: Arc::new(PoolInner {
                connector,
                host_cooldowns: Arc::new(Cooldowns::new(limits.cooldown_initial, limits.cooldown_max)),
                dc_cooldowns: Cooldowns::new(limits.cooldown_initial, limits.cooldown_max),
                limits,
                lanes: Mutex::new(HashMap::new()),
                setups: Mutex::new(HashMap::new()),
                closed: AtomicBool::new(false),
                epoch: Mutex::new(CancellationToken::new()),
                generation: AtomicU64::new(0),
                next_lane: AtomicU64::new(0),
                next_channel: AtomicU64::new(0),
            }),
        }
    }

    pub fn lane_count(&self) -> usize {
        self.inner.lanes.lock().len()
    }

    pub fn lane(&self, host: &str) -> Option<Arc<Lane>> {
        self.inner.lanes.lock().get(host).cloned()
    }

    pub fn setup_running(&self, dc: i32) -> bool {
        self.inner.setups.lock().contains_key(&dc)
    }

    /// Открыть канал для медиа-соединения DC без ожидания: готовый lane —
    /// канал; иначе None (соединение идёт по WS) и фоновый preflight.
    pub fn try_open(&self, dc: i32, label: &str) -> Result<Option<Arc<Channel>>, H2Error> {
        let inner = &self.inner;
        if inner.closed.load(Ordering::Acquire) {
            return Err(H2Error::Closed("H2 pool closed"));
        }
        if !DC_DEFAULT_IPS.contains_key(&dc) {
            ldebug!("[{}] H2 unsupported DC{} -> existing WS route", label, dc);
            return Ok(None);
        }
        let now = Instant::now();
        if inner.dc_cooldowns.active(&dc.to_string(), now) {
            return Ok(None);
        }
        let domains = crate::balancer::BALANCER.read().get_domains_for_dc(dc);
        if domains.is_empty() {
            return Ok(None);
        }
        for base in &domains {
            if crate::cf_websocket::cf_tls_in_cooldown(base) {
                continue;
            }
            let host = format!("kws{}.{}", dc, base);
            if inner.host_cooldowns.active(&host, now) {
                continue;
            }
            let Some(lane) = inner.lanes.lock().get(&host).cloned() else {
                continue;
            };
            if lane.is_closed() {
                continue;
            }
            let id = inner.next_channel.fetch_add(1, Ordering::Relaxed) + 1;
            let Some(channel) = Channel::new(lane.clone(), id, label) else {
                continue;
            };
            if crate::balancer::BALANCER.write().update_domain_for_dc(dc, base) {
                linfo!(" CF домен для DC{} -> {} (H2)", dc, base);
            }
            linfo!(
                "[{}] ROUTE DC{} media -> H2 lane={} channel={} host={} channels={} tcp_connections={}",
                label,
                dc,
                lane.id,
                channel.id,
                host,
                lane.channel_count(),
                lane.tcp_connections.load(Ordering::Relaxed)
            );
            return Ok(Some(channel));
        }
        self.spawn_setup(dc, domains);
        ldebug!("[{}] H2 DC{} has no ready lane; using WS", label, dc);
        Ok(None)
    }

    fn spawn_setup(&self, dc: i32, domains: Vec<String>) {
        let inner = self.inner.clone();
        let generation = inner.generation.load(Ordering::Acquire);
        {
            let mut setups = inner.setups.lock();
            if setups.contains_key(&dc) {
                return;
            }
            setups.insert(dc, generation);
        }
        let epoch = inner.epoch.lock().clone();
        tokio::spawn(async move {
            let timeout = inner.limits.setup_timeout;
            let result = tokio::select! {
                _ = epoch.cancelled() => None,
                r = tokio::time::timeout(timeout, inner.setup(dc, domains, generation)) => Some(r),
            };
            let key = dc.to_string();
            match result {
                Some(Ok(true)) => inner.dc_cooldowns.record_success(&key),
                Some(Ok(false)) => {
                    let cd = inner.dc_cooldowns.record_failure(&key, Instant::now());
                    lwarn!("H2 DC{} unavailable; using WS for {}s", dc, cd.as_secs());
                }
                Some(Err(_)) => {
                    STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                    let cd = inner.dc_cooldowns.record_failure(&key, Instant::now());
                    lwarn!("H2 DC{} setup timed out; using WS for {}s", dc, cd.as_secs());
                }
                None => {}
            }
            let mut setups = inner.setups.lock();
            if setups.get(&dc) == Some(&generation) {
                setups.remove(&dc);
            }
        });
    }

    async fn close_lanes(&self) {
        let lanes: Vec<Arc<Lane>> = self.inner.lanes.lock().drain().map(|(_, l)| l).collect();
        futures_join_all(lanes.iter().map(|l| l.close())).await;
    }

    /// StopProxy: закрыть всё, новые каналы не открывать.
    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.generation.fetch_add(1, Ordering::AcqRel);
        self.inner.epoch.lock().cancel();
        self.close_lanes().await;
    }

    /// Смена сети: закрыть lane и сбросить cooldown — старые соединения и
    /// неудачи относятся к прежней сети.
    pub async fn reset(&self) {
        self.inner.generation.fetch_add(1, Ordering::AcqRel);
        {
            let mut epoch = self.inner.epoch.lock();
            epoch.cancel();
            *epoch = CancellationToken::new();
        }
        self.inner.setups.lock().clear();
        // Сначала закрыть lane: оборванные запросы не должны записать
        // неудачу в уже очищенные cooldown новой сети.
        self.close_lanes().await;
        self.inner.host_cooldowns.clear();
        self.inner.dc_cooldowns.clear();
    }
}

impl Default for H2Pool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Тесты: сценарии tests/test_cf_h2.py, test_h2_transport.py десктопа на
// локальном h2::server поверх tokio::io::duplex.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub type Handler = Arc<
        dyn Fn(http::Method, Bytes, Responder) -> Pin<Box<dyn Future<Output = ()> + Send>>
            + Send
            + Sync,
    >;

    pub fn handler<F, Fut>(f: F) -> Handler
    where
        F: Fn(http::Method, Bytes, Responder) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Arc::new(move |m, b, r| Box::pin(f(m, b, r)))
    }

    pub struct Responder(pub h2::server::SendResponse<Bytes>);

    impl Responder {
        pub fn stream(mut self, status: u16, headers: &[(&str, &str)]) -> h2::SendStream<Bytes> {
            let mut b = http::Response::builder().status(status);
            for (k, v) in headers {
                b = b.header(*k, *v);
            }
            self.0.send_response(b.body(()).unwrap(), false).unwrap()
        }

        pub fn full(self, status: u16, body: &[u8]) {
            self.full_with(status, &[], body)
        }

        pub fn full_with(mut self, status: u16, headers: &[(&str, &str)], body: &[u8]) {
            let mut b = http::Response::builder().status(status);
            for (k, v) in headers {
                b = b.header(*k, *v);
            }
            let mut s = self.0.send_response(b.body(()).unwrap(), body.is_empty()).unwrap();
            if !body.is_empty() {
                s.send_data(Bytes::copy_from_slice(body), true).unwrap();
            }
        }
    }

    pub struct TestServer {
        pub handler: Mutex<Handler>,
        pub connects: AtomicUsize,
        pub calls: Mutex<Vec<(http::Method, Bytes, Instant)>>,
        pub kills: Mutex<Vec<CancellationToken>>,
        pub refuse: AtomicBool,
        pub refuse_hosts: Mutex<HashSet<String>>,
        pub hosts: Mutex<Vec<String>>,
    }

    impl TestServer {
        pub fn new(h: Handler) -> Arc<TestServer> {
            Arc::new(TestServer {
                handler: Mutex::new(h),
                connects: AtomicUsize::new(0),
                calls: Mutex::new(Vec::new()),
                kills: Mutex::new(Vec::new()),
                refuse: AtomicBool::new(false),
                refuse_hosts: Mutex::new(HashSet::new()),
                hosts: Mutex::new(Vec::new()),
            })
        }

        /// Тела POST-запросов в порядке прихода.
        pub fn posts(&self) -> Vec<Bytes> {
            self.calls
                .lock()
                .iter()
                .filter(|(m, _, _)| m == http::Method::POST)
                .map(|(_, b, _)| b.clone())
                .collect()
        }

        pub fn heads(&self) -> usize {
            self.calls
                .lock()
                .iter()
                .filter(|(m, _, _)| m == http::Method::HEAD)
                .count()
        }

        pub fn kill_all(&self) {
            for k in self.kills.lock().iter() {
                k.cancel();
            }
        }
    }

    impl Connector for Arc<TestServer> {
        fn connect<'a>(&'a self, host: &'a str) -> ConnectFuture<'a> {
            Box::pin(async move {
                self.hosts.lock().push(host.to_string());
                if self.refuse.load(Ordering::Relaxed) || self.refuse_hosts.lock().contains(host) {
                    return Err(H2Error::Io("refused".into()));
                }
                self.connects.fetch_add(1, Ordering::Relaxed);
                let (client, server) = tokio::io::duplex(1 << 20);
                let kill = CancellationToken::new();
                self.kills.lock().push(kill.clone());
                let me = self.clone();
                tokio::spawn(async move {
                    let mut conn = match h2::server::Builder::new()
                        .initial_window_size(1 << 20)
                        .initial_connection_window_size(1 << 22)
                        .handshake::<_, Bytes>(server)
                        .await
                    {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    loop {
                        let next = tokio::select! {
                            _ = kill.cancelled() => return,
                            n = conn.accept() => n,
                        };
                        let Some(Ok((req, respond))) = next else { return };
                        let me = me.clone();
                        tokio::spawn(async move {
                            let method = req.method().clone();
                            let mut body = req.into_body();
                            let mut data = BytesMut::new();
                            while let Some(Ok(chunk)) = body.data().await {
                                let _ = body.flow_control().release_capacity(chunk.len());
                                data.extend_from_slice(&chunk);
                            }
                            let data = data.freeze();
                            me.calls.lock().push((method.clone(), data.clone(), Instant::now()));
                            let h = me.handler.lock().clone();
                            h(method, data, Responder(respond)).await;
                        });
                    }
                });
                Ok(Box::new(client) as BoxIo)
            })
        }
    }

    pub fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    pub fn test_limits() -> H2Limits {
        H2Limits {
            request_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(2),
            setup_timeout: Duration::from_secs(2),
            replay: Some(H2ReplayTiming {
                idle: ms(10),
                request: ms(20),
                retry: ms(20),
                slot: Duration::from_secs(30),
                max_age: Duration::from_secs(30),
            }),
            ..H2Limits::default()
        }
    }

    pub fn test_lane(server: &Arc<TestServer>, limits: H2Limits) -> Arc<Lane> {
        Lane::new(
            "kws4.example.org".into(),
            1,
            limits,
            Arc::new(server.clone()),
            Arc::new(Cooldowns::new(Duration::from_secs(30), Duration::from_secs(1800))),
            Weak::new(),
        )
    }

    pub fn test_channel(lane: &Arc<Lane>, id: u64) -> Arc<Channel> {
        Channel::new(lane.clone(), id, "owned-test").unwrap()
    }

    pub fn pending() -> impl Future<Output = ()> {
        std::future::pending::<()>()
    }

    pub async fn wait_until<F: Fn() -> bool>(f: F, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if f() {
                return true;
            }
            tokio::time::sleep(ms(2)).await;
        }
        f()
    }

    /// Пара AES-CTR с одним ключом: шифруем «клиентом», расшифровываем
    /// прокси (как clt_dec/clt_enc после handshake).
    pub fn cipher() -> TrackedStream {
        TrackedStream::new(&[7u8; 32], &[9u8; 16])
    }
}

#[cfg(test)]
mod framing_tests {
    use super::test_support::*;
    use super::*;
    use crate::crypto::PROTO_INTERMEDIATE;

    fn plain_body(declared: u32, payload: usize) -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b.extend_from_slice(&[b'm'; 8]);
        b.extend_from_slice(&declared.to_le_bytes());
        b.extend(vec![b'p'; payload]);
        b
    }

    fn frame_len(len: usize, quick: bool) -> Vec<u8> {
        let v = len as u32 | if quick { 0x8000_0000 } else { 0 };
        v.to_le_bytes().to_vec()
    }

    /// Шифрует `wire` и подаёт его в read_packet побайтно (фрагментация).
    async fn packet(wire: &[u8], proto_type: i32, max_packet: usize) -> Result<(Vec<u8>, bool), PacketError> {
        let mut enc = cipher();
        let mut data = wire.to_vec();
        enc.xor(&mut data);
        let (mut tx, mut rx) = tokio::io::duplex(64);
        let feeder = tokio::spawn(async move {
            for b in data {
                if tx.write_all(&[b]).await.is_err() {
                    return;
                }
            }
        });
        let mut dec = cipher();
        let r = read_packet(&mut rx, &mut dec, proto_type, max_packet).await;
        feeder.abort();
        r
    }

    #[tokio::test]
    async fn fragmented_abridged_extended_and_quick_ack() {
        let body = vec![b'a'; 512];
        let mut wire = vec![0xFF, 0x80, 0x00, 0x00];
        wire.extend_from_slice(&body);
        let (decoded, quick) = packet(&wire, PROTO_ABRIDGED, MAX_PACKET).await.unwrap();
        assert_eq!(decoded, body);
        assert!(quick);
    }

    #[tokio::test]
    async fn intermediate_quick_ack_does_not_change_body() {
        let body = vec![b'a'; 40];
        let mut wire = frame_len(40, true);
        wire.extend_from_slice(&body);
        let (decoded, quick) = packet(&wire, PROTO_INTERMEDIATE, MAX_PACKET).await.unwrap();
        assert_eq!(decoded, body);
        assert!(quick);
    }

    #[tokio::test]
    async fn padded_plaintext_accepts_padding_up_to_256() {
        let body = plain_body(20, 20);
        for padding in 0..=256usize {
            let mut wire = frame_len(body.len() + padding, padding % 2 == 0);
            wire.extend_from_slice(&body);
            wire.extend(vec![b'z'; padding]);
            let (decoded, quick) = packet(&wire, PROTO_PADDED_INTERMEDIATE, MAX_PACKET)
                .await
                .unwrap_or_else(|e| panic!("padding {}: {}", padding, e));
            assert_eq!(decoded, body, "padding {}", padding);
            assert_eq!(quick, padding % 2 == 0);
        }
    }

    #[tokio::test]
    async fn padded_plaintext_preserves_padding_included_in_message_length() {
        let mut body = plain_body(272, 20);
        body.extend(vec![b'd'; 252]);
        let mut wire = frame_len(body.len() + 15, false);
        wire.extend_from_slice(&body);
        wire.extend_from_slice(&[b'z'; 15]);
        let (decoded, _) = packet(&wire, PROTO_PADDED_INTERMEDIATE, MAX_PACKET).await.unwrap();
        assert_eq!(decoded, body);
    }

    #[tokio::test]
    async fn extended_padding_preserves_packet_size_limit() {
        let body = plain_body(20, 20);
        let limit = body.len();
        let mut wire = frame_len(body.len() + 256, false);
        wire.extend_from_slice(&body);
        wire.extend_from_slice(&[b'z'; 256]);
        let (decoded, _) = packet(&wire, PROTO_PADDED_INTERMEDIATE, limit).await.unwrap();
        assert_eq!(decoded, body);
        let oversized = plain_body(24, 24);
        let mut wire = frame_len(oversized.len(), false);
        wire.extend_from_slice(&oversized);
        let e = packet(&wire, PROTO_PADDED_INTERMEDIATE, limit).await.unwrap_err();
        assert!(e.to_string().contains("size"), "{}", e);
        let mut encrypted = vec![b'k'; 8];
        encrypted.extend_from_slice(&[b'm'; 16]);
        encrypted.extend_from_slice(&[b'c'; 32]);
        let mut wire = frame_len(encrypted.len(), false);
        wire.extend_from_slice(&encrypted);
        let e = packet(&wire, PROTO_PADDED_INTERMEDIATE, limit).await.unwrap_err();
        assert!(e.to_string().contains("size"), "{}", e);
    }

    #[tokio::test]
    async fn invalid_plaintext_lengths_and_excess_padding_are_rejected() {
        for (declared, payload, padding) in [
            (0u32, 20usize, 0usize),
            (24, 20, 0),
            (21, 21, 0),
            (20, 20, 257),
            (0xFFFF_FFFF, 20, 0),
        ] {
            let mut body = plain_body(declared, payload);
            body.extend(vec![b'z'; padding]);
            let mut wire = frame_len(body.len(), false);
            wire.extend_from_slice(&body);
            let r = packet(&wire, PROTO_PADDED_INTERMEDIATE, MAX_PACKET).await;
            assert!(
                matches!(r, Err(PacketError::Invalid(_))),
                "declared={} padding={}",
                declared,
                padding
            );
        }
    }

    #[tokio::test]
    async fn padded_ciphertext_removes_full_padding_blocks() {
        let mut body = vec![b'k'; 8];
        body.extend_from_slice(&[b'm'; 16]);
        body.extend_from_slice(&[b'c'; 32]);
        for padding in 0..16usize {
            let mut wire = frame_len(body.len() + padding, false);
            wire.extend_from_slice(&body);
            wire.extend(vec![b'z'; padding]);
            let (decoded, _) = packet(&wire, PROTO_PADDED_INTERMEDIATE, MAX_PACKET).await.unwrap();
            assert_eq!(decoded, body, "padding {}", padding);
        }
    }

    #[tokio::test]
    async fn oversize_header_rejected_before_body_read() {
        // Только заголовок, тела нет: ошибка должна прийти без чтения тела.
        let wire = frame_len(MAX_PACKET + 4, false);
        let e = packet(&wire, PROTO_INTERMEDIATE, MAX_PACKET).await.unwrap_err();
        assert!(e.to_string().contains("length"), "{}", e);
    }

    #[test]
    fn negative_transport_error_keeps_native_framing() {
        let err = (-404i32).to_le_bytes();
        let mut abridged = vec![1u8];
        abridged.extend_from_slice(&err);
        assert_eq!(encode_reply(&err, PROTO_ABRIDGED, MAX_PACKET).unwrap(), abridged);
        let mut inter = vec![4u8, 0, 0, 0];
        inter.extend_from_slice(&err);
        assert_eq!(encode_reply(&err, PROTO_INTERMEDIATE, MAX_PACKET).unwrap(), inter);
        for _ in 0..32 {
            let padded = encode_reply(&err, PROTO_PADDED_INTERMEDIATE, MAX_PACKET).unwrap();
            let len = u32::from_le_bytes(padded[..4].try_into().unwrap()) as usize;
            assert_eq!(len, padded.len() - 4);
            assert!((4..=7).contains(&len));
            assert_eq!(&padded[4..8], &err);
        }
    }

    #[test]
    fn encode_reply_uses_long_abridged_header_and_rejects_bad_lengths() {
        let body = vec![1u8; 0x7F * 4];
        let out = encode_reply(&body, PROTO_ABRIDGED, MAX_PACKET).unwrap();
        assert_eq!(&out[..4], &[0x7F, 0x7F, 0, 0]);
        assert!(encode_reply(&[], PROTO_ABRIDGED, MAX_PACKET).is_err());
        assert!(encode_reply(&[1, 2, 3], PROTO_INTERMEDIATE, MAX_PACKET).is_err());
        assert!(encode_reply(&[0; 8], PROTO_INTERMEDIATE, 4).is_err());
    }

    #[test]
    fn cooldown_grows_and_resets() {
        let cd = Cooldowns::new(Duration::from_secs(30), Duration::from_secs(1800));
        let now = Instant::now();
        let seq: Vec<u64> = (0..8).map(|_| cd.record_failure("h", now).as_secs()).collect();
        assert_eq!(seq, vec![30, 60, 120, 240, 480, 960, 1800, 1800]);
        assert!(cd.active("h", now));
        assert!(!cd.active("h", now + Duration::from_secs(1801)));
        cd.record_success("h");
        assert!(!cd.active("h", now));
        assert_eq!(cd.record_failure("h", now).as_secs(), 30);
    }

    #[test]
    fn replay_profile_follows_network_transport() {
        let _lock = GLOBAL_STATE_TEST_LOCK.blocking_lock();
        let saved = NETWORK_TRANSPORT.load(Ordering::Relaxed);
        NETWORK_TRANSPORT.store(2, Ordering::Relaxed);
        assert_eq!(H2Limits::default().timing(), H2_REPLAY_CELLULAR);
        NETWORK_TRANSPORT.store(1, Ordering::Relaxed);
        assert_eq!(H2Limits::default().timing(), H2_REPLAY_WIFI);
        NETWORK_TRANSPORT.store(0, Ordering::Relaxed);
        assert_eq!(H2Limits::default().timing(), H2_REPLAY_WIFI);
        NETWORK_TRANSPORT.store(saved, Ordering::Relaxed);
        assert_eq!(H2_REPLAY_WIFI.idle, ms(1000));
        assert_eq!(H2_REPLAY_CELLULAR.request, ms(6000));
    }
}

#[cfg(test)]
mod multiplex_tests {
    use super::test_support::*;
    use super::*;
    use crate::crypto::PROTO_INTERMEDIATE;

    fn key_body(tag: u8, n: usize) -> Bytes {
        let mut b = b"samekey!".to_vec();
        b.extend(vec![tag; n]);
        Bytes::from(b)
    }

    async fn recv(ch: &Arc<Channel>) -> Bytes {
        tokio::time::timeout(Duration::from_secs(2), ch.receive())
            .await
            .expect("receive timed out")
            .expect("channel failed")
    }

    fn echo() -> Handler {
        handler(|_m, body, r| async move { r.full(200, &body) })
    }

    #[tokio::test]
    async fn same_auth_prefix_out_of_order_replies_stay_with_source_channel() {
        let release = Arc::new(Notify::new());
        let rel = release.clone();
        let a = key_body(b'a', 32);
        let a2 = a.clone();
        let server = TestServer::new(handler(move |_m, body, r| {
            let rel = rel.clone();
            let a = a2.clone();
            async move {
                if body == a {
                    rel.notified().await;
                }
                r.full(200, &body);
            }
        }));
        let lane = test_lane(&server, test_limits());
        let (first, second) = (test_channel(&lane, 1), test_channel(&lane, 2));
        assert!(first.send(a.clone(), false, false).await.unwrap());
        assert!(wait_until(|| server.posts().len() == 1, ms(1000)).await);
        let b = key_body(b'b', 32);
        second.send(b.clone(), false, false).await.unwrap();
        assert_eq!(recv(&second).await, b);
        release.notify_one();
        assert_eq!(recv(&first).await, a);
        assert_eq!(lane.max_inflight(), 2);
        assert_eq!(server.connects.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn close_one_channel_does_not_cancel_another() {
        let server = TestServer::new(handler(|_m, body, r| async move {
            if body[0] == b'a' {
                pending().await;
            }
            r.full(200, &body)
        }));
        let lane = test_lane(&server, test_limits());
        let (first, second) = (test_channel(&lane, 1), test_channel(&lane, 2));
        first.send(Bytes::from(vec![b'a'; 40]), false, false).await.unwrap();
        first.close().await;
        second.send(Bytes::from(vec![b'b'; 40]), false, false).await.unwrap();
        assert_eq!(recv(&second).await, vec![b'b'; 40]);
        second.close().await;
        assert_eq!((lane.inflight(), lane.queued_bytes()), (0, 0));
        assert!(!lane.is_closed());
        assert_eq!(lane.channel_count(), 0);
    }

    #[tokio::test]
    async fn backpressure_waits_instead_of_dropping_requests() {
        let release = CancellationToken::new();
        let rel = release.clone();
        let server = TestServer::new(handler(move |_m, body, r| {
            let rel = rel.clone();
            async move {
                rel.cancelled().await;
                r.full(200, &body)
            }
        }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        let limit = lane.limits.channel_requests;
        for _ in 0..limit {
            ch.send(Bytes::from(vec![b'x'; 40]), false, false).await.unwrap();
        }
        let ch2 = ch.clone();
        let extra = tokio::spawn(async move { ch2.send(Bytes::from(vec![b'y'; 40]), false, false).await });
        tokio::time::sleep(ms(30)).await;
        assert!(!extra.is_finished());
        assert_eq!(ch.stats().pending, limit);
        release.cancel();
        tokio::time::timeout(Duration::from_secs(2), extra).await.unwrap().unwrap().unwrap();
        let mut ys = 0;
        for _ in 0..=limit {
            if recv(&ch).await[0] == b'y' {
                ys += 1;
            }
        }
        assert_eq!(ys, 1);
    }

    #[tokio::test]
    async fn http_error_closes_only_its_channel_without_replaying_packet() {
        let server = TestServer::new(handler(|_m, _b, r| async move { r.full(503, b"") }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        let rec = tokio::spawn(ch.clone().recover());
        ch.send(Bytes::from(vec![b'x'; 40]), false, false).await.unwrap();
        let e = tokio::time::timeout(Duration::from_secs(2), ch.receive()).await.unwrap().unwrap_err();
        assert!(e.to_string().contains("503"), "{}", e);
        tokio::time::sleep(ms(50)).await;
        assert_eq!(server.posts(), vec![Bytes::from(vec![b'x'; 40])]);
        assert!(ch.is_closed());
        assert!(!lane.is_closed());
        // Ошибка HTTP — повод для cooldown домена (на десктопе failed_until).
        assert!(lane.in_cooldown());
        rec.abort();
    }

    /// Ответ клиенту через bridge_h2 на дуплексе: возвращает (клиентская
    /// сторона, задача моста). Клиентская сторона уже «шифрует» cipher().
    fn spawn_bridge(
        ch: &Arc<Channel>,
        proto: u32,
    ) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (client, proxy) = tokio::io::duplex(1 << 20);
        let (r, w) = tokio::io::split(proxy);
        let task = tokio::spawn(bridge_h2(
            r,
            w,
            ch.clone(),
            cipher(),
            cipher(),
            proto,
            CancellationToken::new(),
        ));
        (client, task)
    }

    async fn client_send(client: &mut tokio::io::DuplexStream, enc: &mut TrackedStream, frame: &[u8]) {
        let mut data = frame.to_vec();
        enc.xor(&mut data);
        client.write_all(&data).await.unwrap();
    }

    async fn client_read(client: &mut tokio::io::DuplexStream, dec: &mut TrackedStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut buf))
            .await
            .expect("client read timed out")
            .unwrap();
        dec.xor(&mut buf);
        buf
    }

    #[tokio::test]
    async fn transport_error_reaches_client_before_close_without_cooling_domain() {
        for proto in [PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE] {
            for status in [403u16, 404, 429, 444] {
                let server = TestServer::new(handler(move |_m, body, r| async move {
                    if body[..] == [b'h'; 40] {
                        r.full(200, &[b'r'; 40]);
                    } else {
                        // Тело HTML у ошибки игнорируется.
                        r.full_with(status, &[("content-type", "text/html")], b"<html></html>");
                    }
                }));
                let lane = test_lane(&server, test_limits());
                let ch = test_channel(&lane, 1);
                let (mut client, task) = spawn_bridge(&ch, proto);
                let (mut enc, mut dec) = (cipher(), cipher());
                let pt = proto_tag_to_type(proto);
                let frame = encode_reply(&[b'k'; 40], pt, MAX_PACKET).unwrap();
                client_send(&mut client, &mut enc, &frame).await;
                let code = (-(status as i32)).to_le_bytes();
                if pt == PROTO_ABRIDGED {
                    let got = client_read(&mut client, &mut dec, 5).await;
                    assert_eq!(got[0], 1);
                    assert_eq!(&got[1..5], &code);
                } else {
                    let head = client_read(&mut client, &mut dec, 4).await;
                    let len = u32::from_le_bytes(head[..4].try_into().unwrap()) as usize;
                    assert!((4..=7).contains(&len), "{}", len);
                    let rest = client_read(&mut client, &mut dec, len).await;
                    assert_eq!(&rest[..4], &code);
                }
                tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
                assert!(ch.close_done());
                assert_eq!(ch.stats().pending, 0);
                assert!(!lane.in_cooldown(), "status {}", status);
                let healthy = test_channel(&lane, 2);
                healthy.send(Bytes::from(vec![b'h'; 40]), false, false).await.unwrap();
                assert_eq!(recv(&healthy).await, vec![b'r'; 40]);
                assert_eq!(server.posts(), vec![Bytes::from(vec![b'k'; 40]), Bytes::from(vec![b'h'; 40])]);
                assert!(!lane.is_closed());
                healthy.close().await;
            }
        }
    }

    #[tokio::test]
    async fn binary_transport_error_is_terminal_without_domain_cooldown() {
        let server = TestServer::new(handler(|_m, _b, r| async move {
            r.full(200, &(-429i32).to_le_bytes())
        }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        ch.send(Bytes::from(vec![b'k'; 40]), false, false).await.unwrap();
        let e = tokio::time::timeout(Duration::from_secs(2), ch.receive()).await.unwrap().unwrap_err();
        assert_eq!(e, H2Error::Transport(-429));
        assert_eq!(ch.transport_error(), Some(-429));
        assert!(!lane.in_cooldown());
    }

    #[tokio::test]
    async fn long_polls_cannot_block_fresh_request_and_retired_packet_recovers() {
        let fresh = key_body(b'n', 32);
        let bodies: Vec<Bytes> = (0..8u8).map(|i| key_body(i, 32)).collect();
        let first = bodies[0].clone();
        let calls = Arc::new(Mutex::new(Vec::<Bytes>::new()));
        let (fresh2, calls2) = (fresh.clone(), calls.clone());
        let server = TestServer::new(handler(move |_m, body, r| {
            let (fresh, first, calls) = (fresh2.clone(), first.clone(), calls2.clone());
            async move {
                calls.lock().push(body.clone());
                if body == fresh {
                    return r.full(200, &[b'n'; 40]);
                }
                if body == first && calls.lock().iter().filter(|b| **b == first).count() == 2 {
                    return r.full(200, &[b'r'; 40]);
                }
                pending().await;
            }
        }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        for b in &bodies {
            ch.send(b.clone(), false, false).await.unwrap();
        }
        assert!(wait_until(|| calls.lock().len() == 8, ms(1000)).await);
        let rec = tokio::spawn(ch.clone().recover());
        tokio::time::timeout(Duration::from_secs(2), ch.send(fresh.clone(), false, false))
            .await
            .unwrap()
            .unwrap();
        let mut got = vec![recv(&ch).await, recv(&ch).await];
        got.sort();
        assert_eq!(got, vec![Bytes::from(vec![b'n'; 40]), Bytes::from(vec![b'r'; 40])]);
        let st = ch.stats();
        assert_eq!(st.capacity_rotations, 1);
        assert_eq!(calls.lock().iter().filter(|b| **b == bodies[0]).count(), 2);
        assert_eq!(lane.max_inflight(), 8);
        assert_eq!(lane.errors.load(Ordering::Relaxed), 0);
        assert!(!ch.is_closed());
        rec.abort();
    }

    #[tokio::test]
    async fn shared_lane_long_polls_cannot_block_new_channel() {
        let fresh = key_body(b'n', 32);
        let f2 = fresh.clone();
        let server = TestServer::new(handler(move |_m, body, r| {
            let fresh = f2.clone();
            async move {
                if body == fresh {
                    return r.full(200, &[b'n'; 40]);
                }
                pending().await;
            }
        }));
        let limits = H2Limits {
            lane_requests: 2,
            ..test_limits()
        };
        let lane = test_lane(&server, limits);
        let (a, b, waiting) = (test_channel(&lane, 1), test_channel(&lane, 2), test_channel(&lane, 3));
        a.send(key_body(b'a', 32), false, false).await.unwrap();
        b.send(key_body(b'b', 32), false, false).await.unwrap();
        assert!(wait_until(|| server.posts().len() == 2, ms(1000)).await);
        let rec = tokio::spawn(waiting.clone().recover());
        tokio::time::timeout(Duration::from_secs(2), waiting.send(fresh, false, false))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recv(&waiting).await, vec![b'n'; 40]);
        assert_eq!(a.stats().capacity_rotations + b.stats().capacity_rotations, 1);
        assert_eq!(a.stats().pending + b.stats().pending, 1);
        assert_eq!(lane.capacity_rotations.load(Ordering::Relaxed), 1);
        assert_eq!(lane.max_inflight(), 2);
        rec.abort();
    }

    #[tokio::test]
    async fn capacity_rotation_never_retires_plaintext_or_unretained_request() {
        let release = CancellationToken::new();
        let rel = release.clone();
        let server = TestServer::new(handler(move |_m, _b, r| {
            let rel = rel.clone();
            async move {
                rel.cancelled().await;
                r.full(200, &[b'r'; 40])
            }
        }));
        let limits = H2Limits {
            channel_requests: 2,
            replay: Some(H2ReplayTiming {
                request: ms(5),
                ..test_limits().replay.unwrap()
            }),
            ..test_limits()
        };
        let lane = test_lane(&server, limits);
        let ch = test_channel(&lane, 1);
        let mut plain = vec![0u8; 8];
        plain.extend_from_slice(&[b'p'; 32]);
        ch.send(Bytes::from(plain), false, false).await.unwrap();
        ch.send(key_body(b'u', 64 * 1024), false, false).await.unwrap();
        let ch2 = ch.clone();
        let extra = tokio::spawn(async move { ch2.send(key_body(b'n', 32), false, false).await });
        let rec = tokio::spawn(ch.clone().recover());
        tokio::time::sleep(ms(60)).await;
        assert!(!extra.is_finished());
        assert_eq!(ch.stats().capacity_rotations, 0);
        release.cancel();
        tokio::time::timeout(Duration::from_secs(2), extra).await.unwrap().unwrap().unwrap();
        rec.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn close_releases_request_cancelled_before_it_started() {
        let server = TestServer::new(handler(|_m, _b, _r| async move {
            panic!("cancelled request reached HTTP");
        }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        // current_thread: задача запроса ещё не опрашивалась.
        ch.send(key_body(b'k', 32), false, false).await.unwrap();
        ch.close().await;
        ch.close().await;
        assert_eq!((lane.inflight(), lane.queued_bytes()), (0, 0));
        assert_eq!(ch.stats().pending, 0);
        assert_eq!(ch.stats().pending_bytes, 0);
        assert!(server.posts().is_empty());
    }

    #[tokio::test]
    async fn preflight_accepts_2xx_405_501_and_rejects_others() {
        for (status, ok) in [(200u16, true), (204, true), (405, true), (501, true), (404, false), (403, false), (502, false)] {
            let server = TestServer::new(handler(move |m, _b, r| async move {
                assert_eq!(m, http::Method::HEAD);
                r.full(status, b"")
            }));
            let lane = test_lane(&server, test_limits());
            let r = lane.preflight().await;
            assert_eq!(r.is_ok(), ok, "status {} -> {:?}", status, r);
            if !ok {
                let e = r.unwrap_err().to_string();
                assert!(e.contains(&format!("preflight HTTP {}", status)), "{}", e);
            }
        }
    }

    #[tokio::test]
    async fn preflight_and_posts_share_one_connection() {
        let server = TestServer::new(echo());
        let lane = test_lane(&server, test_limits());
        lane.preflight().await.unwrap();
        let ch = test_channel(&lane, 1);
        for i in 0..5u8 {
            ch.send(key_body(i, 32), false, false).await.unwrap();
            recv(&ch).await;
        }
        assert_eq!(server.connects.load(Ordering::Relaxed), 1);
        assert_eq!(lane.tcp_connections.load(Ordering::Relaxed), 1);
    }

    /// Ответ кусками: первый кусок, затем по сигналу остальное (или сброс).
    async fn packet_bridge(content_length: bool, truncate: bool, concurrent_small: bool) {
        let body: Vec<u8> = vec![b'x'; 64 * 1024 + 40];
        let first_read = CancellationToken::new();
        let release = CancellationToken::new();
        let (fr, rel, b2) = (first_read.clone(), release.clone(), body.clone());
        let server = TestServer::new(handler(move |_m, req, r| {
            let (fr, rel, body) = (fr.clone(), rel.clone(), b2.clone());
            async move {
                if req[..] == [b's'; 40] {
                    return r.full(200, &[b'z'; 40]);
                }
                let len = body.len().to_string();
                let headers: Vec<(&str, &str)> = if content_length {
                    vec![("content-length", len.as_str())]
                } else {
                    vec![]
                };
                let mut s = r.stream(200, &headers);
                s.send_data(Bytes::copy_from_slice(&body[..16384]), false).unwrap();
                fr.cancel();
                rel.cancelled().await;
                if truncate {
                    s.send_reset(h2::Reason::INTERNAL_ERROR);
                } else {
                    s.send_data(Bytes::copy_from_slice(&body[16384..]), true).unwrap();
                }
                // Держим поток, пока клиент читает.
                tokio::time::sleep(ms(200)).await;
            }
        }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        let (mut client, task) = spawn_bridge(&ch, PROTO_TAG_INTERMEDIATE);
        let (mut enc, mut dec) = (cipher(), cipher());
        let frame = encode_reply(&[b'l'; 40], PROTO_INTERMEDIATE, MAX_PACKET).unwrap();
        client_send(&mut client, &mut enc, &frame).await;
        tokio::time::timeout(Duration::from_secs(2), first_read.cancelled()).await.unwrap();
        tokio::time::sleep(ms(20)).await;
        if concurrent_small {
            let small = encode_reply(&[b's'; 40], PROTO_INTERMEDIATE, MAX_PACKET).unwrap();
            client_send(&mut client, &mut enc, &small).await;
            let got = client_read(&mut client, &mut dec, 44).await;
            assert_eq!(got, encode_reply(&[b'z'; 40], PROTO_INTERMEDIATE, MAX_PACKET).unwrap());
        }
        release.cancel();
        if truncate {
            tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
            assert!(ch.is_closed());
            let mut rest = Vec::new();
            let _ = client.read_to_end(&mut rest).await;
            assert!(rest.is_empty(), "partial reply must not reach the client");
        } else {
            let got = client_read(&mut client, &mut dec, 4 + body.len()).await;
            assert_eq!(&got[..4], &(body.len() as u32).to_le_bytes());
            assert_eq!(&got[4..], &body[..]);
            drop(client);
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
    }

    #[tokio::test]
    async fn native_frame_starts_only_after_entire_body_is_available() {
        packet_bridge(true, false, false).await;
    }

    #[tokio::test]
    async fn ready_reply_bypasses_incomplete_large_response_on_same_channel() {
        packet_bridge(true, false, true).await;
    }

    #[tokio::test]
    async fn response_without_length_uses_buffered_framing() {
        packet_bridge(false, false, false).await;
    }

    #[tokio::test]
    async fn truncated_stream_closes_native_channel() {
        packet_bridge(true, true, false).await;
    }

    #[tokio::test]
    async fn lane_reply_memory_bound_and_cancellation_cleanup() {
        let started = CancellationToken::new();
        let st2 = started.clone();
        let server = TestServer::new(handler(move |_m, body, r| {
            let started = st2.clone();
            async move {
                if body[..] == [b'a'; 40] {
                    let mut s = r.stream(200, &[]);
                    s.send_data(Bytes::from(vec![b'r'; 32]), false).unwrap();
                    started.cancel();
                    pending().await;
                } else {
                    r.full(200, &[b'r'; 16])
                }
            }
        }));
        let limits = H2Limits {
            lane_reply_bytes: 40,
            ..test_limits()
        };
        let lane = test_lane(&server, limits);
        let slow = test_channel(&lane, 1);
        slow.send(Bytes::from(vec![b'a'; 40]), false, false).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), started.cancelled()).await.unwrap();
        assert!(wait_until(|| lane.reply_buffer_bytes() == 32, ms(1000)).await);
        let e = lane.post(Bytes::from(vec![b'b'; 40]), None, false).await.unwrap_err();
        assert_eq!(e, H2Error::ReplyBufferFull);
        assert_eq!(lane.reply_buffer_bytes(), 32);
        assert!(!lane.in_cooldown());
        slow.close().await;
        assert_eq!(slow.stats().receiving, 0);
        assert_eq!(lane.reply_buffer_bytes(), 0);
        assert_eq!(lane.post(Bytes::from(vec![b'b'; 40]), None, false).await.unwrap(), vec![b'r'; 16]);
    }

    #[tokio::test]
    async fn native_disconnect_does_not_cool_down_healthy_lane() {
        let server = TestServer::new(handler(|_m, _b, r| async move { r.full(200, &[b'r'; 65536]) }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        let (client, proxy) = tokio::io::duplex(1 << 20);
        let (r, w) = tokio::io::split(proxy);
        let (cr, cw) = tokio::io::split(client);
        let mut enc = cipher();
        let mut frame = encode_reply(&[b'x'; 40], PROTO_INTERMEDIATE, MAX_PACKET).unwrap();
        enc.xor(&mut frame);
        let mut cw = cw;
        cw.write_all(&frame).await.unwrap();
        // Клиент ушёл: запись ответа в закрытую сторону падает.
        drop(cr);
        drop(cw);
        tokio::time::timeout(
            Duration::from_secs(2),
            bridge_h2(r, w, ch.clone(), cipher(), cipher(), PROTO_TAG_INTERMEDIATE, CancellationToken::new()),
        )
        .await
        .unwrap();
        assert!(ch.is_closed());
        assert!(!lane.in_cooldown());
        assert_eq!(lane.errors.load(Ordering::Relaxed), 0);
        let healthy = test_channel(&lane, 2);
        healthy.send(Bytes::from(vec![b'h'; 40]), false, false).await.unwrap();
        assert_eq!(recv(&healthy).await.len(), 65536);
    }

    #[tokio::test]
    async fn slow_receiver_queue_overflow_does_not_break_other_channels() {
        let server = TestServer::new(echo());
        let limits = H2Limits {
            channel_bytes: 80,
            ..test_limits()
        };
        let lane = test_lane(&server, limits);
        let (slow, healthy) = (test_channel(&lane, 1), test_channel(&lane, 2));
        for _ in 0..3 {
            slow.send(Bytes::from(vec![b's'; 40]), false, false).await.unwrap();
            assert!(wait_until(|| slow.stats().pending == 0, ms(1000)).await);
        }
        let e = tokio::time::timeout(Duration::from_secs(2), slow.receive()).await.unwrap().unwrap_err();
        assert!(matches!(e, H2Error::Buffer(_)), "{:?}", e);
        healthy.send(Bytes::from(vec![b'h'; 40]), false, false).await.unwrap();
        assert_eq!(recv(&healthy).await, vec![b'h'; 40]);
        assert!(!lane.is_closed());
    }

    #[tokio::test]
    async fn read_timeout_on_last_stream_reconnects_instead_of_reusing_silent_connection() {
        let server = TestServer::new(handler(|_m, body, r| async move {
            if body[0] == b'q' {
                pending().await;
            }
            r.full(200, &body)
        }));
        let limits = H2Limits {
            request_timeout: ms(150),
            ..test_limits()
        };
        let lane = test_lane(&server, limits);
        let ch = test_channel(&lane, 1);
        ch.send(Bytes::from(vec![b'q'; 40]), false, false).await.unwrap();
        let e = tokio::time::timeout(Duration::from_secs(2), ch.receive()).await.unwrap().unwrap_err();
        assert_eq!(e, H2Error::Timeout("H2 stream read"));
        let other = test_channel(&lane, 2);
        other.send(Bytes::from(vec![b'o'; 40]), false, false).await.unwrap();
        assert_eq!(recv(&other).await, vec![b'o'; 40]);
        assert_eq!(server.connects.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn read_timeout_with_other_active_stream_keeps_connection() {
        let server = TestServer::new(handler(|_m, body, r| async move {
            if body[0] == b'q' {
                pending().await;
            }
            if body[0] == b'w' {
                tokio::time::sleep(ms(400)).await;
            }
            r.full(200, &body)
        }));
        let limits = H2Limits {
            request_timeout: ms(150),
            ..test_limits()
        };
        let lane = test_lane(&server, limits);
        let (a, b) = (test_channel(&lane, 1), test_channel(&lane, 2));
        a.send(Bytes::from(vec![b'q'; 40]), false, false).await.unwrap();
        tokio::time::sleep(ms(100)).await;
        // Второй поток получает данные (заголовки ждёт < таймаута дважды
        // нельзя: ответ через 400 мс), но он активен в момент таймаута первого.
        b.send(Bytes::from(vec![b'w'; 40]), false, false).await.unwrap();
        let e = tokio::time::timeout(Duration::from_secs(2), a.receive()).await.unwrap().unwrap_err();
        assert_eq!(e, H2Error::Timeout("H2 stream read"));
        assert_eq!(server.connects.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn connection_loss_fails_pending_and_next_request_reconnects() {
        let server = TestServer::new(handler(|_m, body, r| async move {
            if body[0] == b'q' {
                pending().await;
            }
            r.full(200, &body)
        }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        ch.send(Bytes::from(vec![b'q'; 40]), false, false).await.unwrap();
        assert!(wait_until(|| server.posts().len() == 1, ms(1000)).await);
        server.kill_all();
        let e = tokio::time::timeout(Duration::from_secs(2), ch.receive()).await.unwrap().unwrap_err();
        assert!(matches!(e, H2Error::Io(_) | H2Error::Protocol(_)), "{:?}", e);
        let other = test_channel(&lane, 2);
        other.send(Bytes::from(vec![b'o'; 40]), false, false).await.unwrap();
        assert_eq!(recv(&other).await, vec![b'o'; 40]);
        assert_eq!(server.connects.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn large_upload_and_download_cross_flow_control_windows() {
        let server = TestServer::new(echo());
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        let big = key_body(b'L', 1024 * 1024);
        ch.send(big.clone(), false, false).await.unwrap();
        assert_eq!(recv(&ch).await, big);
    }

    #[tokio::test]
    async fn lane_close_closes_channels_and_rejects_new_requests() {
        let server = TestServer::new(handler(|_m, _b, _r| async move { pending().await }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        ch.send(Bytes::from(vec![b'q'; 40]), false, false).await.unwrap();
        lane.close().await;
        assert!(ch.close_done());
        assert_eq!(lane.inflight(), 0);
        assert!(Channel::new(lane.clone(), 2, "late").is_none());
        let e = lane.post(Bytes::from(vec![b'x'; 40]), None, false).await.unwrap_err();
        assert!(matches!(e, H2Error::Closed(_)), "{:?}", e);
    }
}

#[cfg(test)]
mod replay_tests {
    use super::test_support::*;
    use super::*;

    fn key_body(tag: u8, n: usize) -> Bytes {
        let mut b = b"samekey!".to_vec();
        b.extend(vec![tag; n]);
        Bytes::from(b)
    }

    async fn recv(ch: &Arc<Channel>) -> Bytes {
        tokio::time::timeout(Duration::from_secs(2), ch.receive())
            .await
            .expect("receive timed out")
            .expect("channel failed")
    }

    fn timing(idle: u64, request: u64, retry: u64) -> H2Limits {
        H2Limits {
            replay: Some(H2ReplayTiming {
                idle: ms(idle),
                request: ms(request),
                retry: ms(retry),
                slot: Duration::from_secs(30),
                max_age: Duration::from_secs(30),
            }),
            ..test_limits()
        }
    }

    fn calls_of(server: &TestServer, body: &Bytes) -> Vec<Instant> {
        server
            .calls
            .lock()
            .iter()
            .filter(|(m, b, _)| m == http::Method::POST && b == body)
            .map(|(_, _, t)| *t)
            .collect()
    }

    #[tokio::test]
    async fn recovery_pauses_during_body_receive_and_resumes_afterwards() {
        let started = CancellationToken::new();
        let release = CancellationToken::new();
        let n = Arc::new(AtomicUsize::new(0));
        let (st2, rel2, n2) = (started.clone(), release.clone(), n.clone());
        let server = TestServer::new(handler(move |_m, _b, r| {
            let (started, release, n) = (st2.clone(), rel2.clone(), n2.clone());
            async move {
                if n.fetch_add(1, Ordering::SeqCst) == 0 {
                    let mut s = r.stream(200, &[]);
                    s.send_data(Bytes::from(vec![b'r'; 20]), false).unwrap();
                    started.cancel();
                    release.cancelled().await;
                    s.send_data(Bytes::from(vec![b'r'; 20]), true).unwrap();
                    tokio::time::sleep(ms(100)).await;
                } else {
                    r.full(200, &[b's'; 40]);
                }
            }
        }));
        let lane = test_lane(&server, timing(10, 20, 20));
        let ch = test_channel(&lane, 1);
        let body = Bytes::from(vec![b'x'; 40]);
        ch.send(body.clone(), false, false).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), started.cancelled()).await.unwrap();
        let rec = tokio::spawn(ch.clone().recover());
        tokio::time::sleep(ms(60)).await;
        assert_eq!(server.posts().len(), 1);
        assert_eq!(ch.stats().receiving, 1);
        release.cancel();
        assert_eq!(recv(&ch).await, vec![b'r'; 40]);
        assert_eq!(recv(&ch).await, vec![b's'; 40]);
        assert_eq!(server.posts(), vec![body.clone(), body]);
        assert_eq!(ch.stats().receiving, 0);
        assert_eq!(lane.reply_buffer_bytes(), 0);
        rec.abort();
    }

    #[tokio::test]
    async fn recovery_reuses_exact_ciphertext_when_original_http_is_still_pending() {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let server = TestServer::new(handler(move |_m, _b, r| {
            let n = n2.clone();
            async move {
                if n.fetch_add(1, Ordering::SeqCst) == 0 {
                    pending().await;
                }
                r.full(200, &[b'r'; 40]);
            }
        }));
        let lane = test_lane(&server, timing(1000, 10, 1000));
        let ch = test_channel(&lane, 1);
        let body = Bytes::from_static(b"opaque-key-and-message-id-xxxxxxxxxxxxxxx");
        let body = body.slice(..40);
        ch.send(body.clone(), false, false).await.unwrap();
        assert!(wait_until(|| server.posts().len() == 1, ms(1000)).await);
        let rec = tokio::spawn(ch.clone().recover());
        assert_eq!(recv(&ch).await, vec![b'r'; 40]);
        assert_eq!(server.posts(), vec![body.clone(), body]);
        assert_eq!(ch.stats().replay_requests, 1);
        assert_eq!(lane.max_inflight(), 2);
        rec.abort();
        ch.close().await;
        assert_eq!(ch.stats().pending, 0);
        assert_eq!(lane.inflight(), 0);
    }

    #[tokio::test]
    async fn recovery_after_http_finished_without_native_reply() {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let server = TestServer::new(handler(move |_m, _b, r| {
            let n = n2.clone();
            async move {
                if n.fetch_add(1, Ordering::SeqCst) == 0 {
                    r.full(200, b"");
                } else {
                    r.full(200, &[b'r'; 40]);
                }
            }
        }));
        let lane = test_lane(&server, timing(10, 20, 1000));
        let ch = test_channel(&lane, 1);
        let body = Bytes::from(vec![b'k'; 40]);
        ch.send(body.clone(), false, false).await.unwrap();
        assert!(wait_until(|| ch.stats().pending == 0, ms(1000)).await);
        let rec = tokio::spawn(ch.clone().recover());
        assert_eq!(recv(&ch).await, vec![b'r'; 40]);
        tokio::time::sleep(ms(40)).await;
        assert_eq!(server.posts(), vec![body.clone(), body]);
        rec.abort();
    }

    #[tokio::test]
    async fn idle_receiver_preserves_capacity_for_new_native_request() {
        let bodies: Vec<Bytes> = (0..4u8).map(|i| key_body(i, 32)).collect();
        let seen = Arc::new(Mutex::new(Vec::<Bytes>::new()));
        let probes = CancellationToken::new();
        let (seen2, probes2) = (seen.clone(), probes.clone());
        let server = TestServer::new(handler(move |_m, body, r| {
            let (seen, probes) = (seen2.clone(), probes2.clone());
            async move {
                let repeat = {
                    let mut s = seen.lock();
                    s.push(body.clone());
                    if s.len() == 4 {
                        probes.cancel();
                    }
                    s.iter().filter(|b| **b == body).count() > 1
                };
                if repeat {
                    pending().await;
                }
                r.full(200, &[b'r'; 40]);
            }
        }));
        let lane = test_lane(&server, timing(10, 20, 20));
        let ch = test_channel(&lane, 1);
        for b in &bodies[..3] {
            ch.send(b.clone(), false, false).await.unwrap();
            recv(&ch).await;
        }
        let rec = tokio::spawn(ch.clone().recover());
        tokio::time::timeout(Duration::from_secs(2), probes.cancelled()).await.unwrap();
        tokio::time::sleep(ms(40)).await;
        assert_eq!(ch.stats().replay_requests, 1);
        assert_eq!(ch.stats().replay_pending, 1);
        tokio::time::timeout(Duration::from_secs(2), ch.send(bodies[3].clone(), false, false))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recv(&ch).await, vec![b'r'; 40]);
        assert_eq!(seen.lock()[3], bodies[2]);
        rec.abort();
        tokio::join!(ch.close(), ch.close());
        assert_eq!(lane.inflight(), 0);
        assert_eq!(ch.stats().pending_bytes, 0);
        assert_eq!(ch.stats().replay_pending, 0);
    }

    #[tokio::test]
    async fn handshake_and_expired_ciphertext_are_never_replayed() {
        let server = TestServer::new(handler(|_m, _b, r| async move { r.full(200, &[b'r'; 40]) }));
        let mut limits = timing(10, 20, 20);
        limits.replay.as_mut().unwrap().max_age = Duration::ZERO;
        let lane = test_lane(&server, limits);
        let ch = test_channel(&lane, 1);
        let mut handshake = vec![0u8; 8];
        handshake.extend_from_slice(&[b'h'; 32]);
        for body in [Bytes::from(handshake), Bytes::from(vec![b'k'; 40])] {
            ch.send(body, false, false).await.unwrap();
            recv(&ch).await;
        }
        tokio::time::sleep(ms(5)).await;
        let rec = tokio::spawn(ch.clone().recover());
        tokio::time::sleep(ms(60)).await;
        assert_eq!(server.posts().len(), 2);
        rec.abort();
    }

    #[tokio::test]
    async fn unhelpful_replies_do_not_cause_unbounded_recovery() {
        let server = TestServer::new(handler(|_m, _b, r| async move { r.full(200, b"") }));
        let lane = test_lane(&server, timing(5, 20, 20));
        let ch = test_channel(&lane, 1);
        let bodies = [key_body(0, 32), key_body(1, 32)];
        for b in &bodies {
            ch.send(b.clone(), false, false).await.unwrap();
        }
        assert!(wait_until(|| ch.stats().pending == 0, ms(1000)).await);
        let rec = tokio::spawn(ch.clone().recover());
        assert!(wait_until(|| server.posts().len() >= 5, ms(2000)).await);
        tokio::time::sleep(ms(80)).await;
        let older = calls_of(&server, &bodies[0]);
        let latest = calls_of(&server, &bodies[1]);
        // Завершённая история не опрашивается; последний пакет — 1 + 3 раза.
        assert_eq!(older.len(), 1);
        assert_eq!(latest.len(), 4);
        for w in latest[1..].windows(2) {
            assert!(w[1] - w[0] >= ms(19), "{:?}", w[1] - w[0]);
        }
        let st = ch.stats();
        assert_eq!((st.pending, st.replay_pending), (0, 0));
        assert_eq!(lane.inflight(), 0);
        // Бюджет исчерпан: задача повторов спит без таймеров.
        let passes = st.recovery_passes;
        tokio::time::sleep(ms(150)).await;
        assert_eq!(ch.stats().recovery_passes, passes);
        rec.abort();
    }

    #[tokio::test]
    async fn new_replies_refresh_idle_receiver_budget_without_native_upload() {
        let replies: Vec<Bytes> = (0..6u8).map(|i| key_body(i, 32)).collect();
        let n = Arc::new(AtomicUsize::new(0));
        let exhausted = CancellationToken::new();
        let (n2, r2, ex2) = (n.clone(), replies.clone(), exhausted.clone());
        let server = TestServer::new(handler(move |_m, _b, r| {
            let (n, replies, exhausted) = (n2.clone(), r2.clone(), ex2.clone());
            async move {
                let count = n.fetch_add(1, Ordering::SeqCst) + 1;
                if count == replies.len() + 3 {
                    exhausted.cancel();
                }
                if count <= replies.len() {
                    r.full(200, &replies[count - 1]);
                } else {
                    r.full(200, b"");
                }
            }
        }));
        let lane = test_lane(&server, timing(5, 20, 10));
        let ch = test_channel(&lane, 1);
        let body = key_body(b'a', 32);
        ch.send(body.clone(), false, false).await.unwrap();
        let rec = tokio::spawn(ch.clone().recover());
        for reply in &replies {
            assert_eq!(&recv(&ch).await, reply);
        }
        tokio::time::timeout(Duration::from_secs(2), exhausted.cancelled()).await.unwrap();
        tokio::time::sleep(ms(60)).await;
        assert_eq!(server.posts(), vec![body; replies.len() + 3]);
        let st = ch.stats();
        assert_eq!((st.pending, st.replay_pending), (0, 0));
        rec.abort();
    }

    #[tokio::test]
    async fn duplicate_reply_does_not_refresh_idle_receiver_budget() {
        let server = TestServer::new(handler(|_m, _b, r| async move { r.full(200, &[b'r'; 40]) }));
        let lane = test_lane(&server, timing(5, 20, 10));
        let ch = test_channel(&lane, 1);
        ch.send(key_body(b'a', 32), false, false).await.unwrap();
        let rec = tokio::spawn(ch.clone().recover());
        for _ in 0..4 {
            assert_eq!(recv(&ch).await, vec![b'r'; 40]);
        }
        tokio::time::sleep(ms(60)).await;
        assert_eq!(server.posts().len(), 4);
        let st = ch.stats();
        assert_eq!((st.pending, st.replay_pending), (0, 0));
        rec.abort();
    }

    #[tokio::test]
    async fn old_pending_request_has_bounded_retries_after_newer_requests() {
        let body = key_body(b't', 32);
        let attempts = Arc::new(AtomicUsize::new(0));
        let (b2, a2) = (body.clone(), attempts.clone());
        let server = TestServer::new(handler(move |_m, req, r| {
            let (body, attempts) = (b2.clone(), a2.clone());
            async move {
                if req == body && attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    pending().await;
                }
                r.full(200, b"");
            }
        }));
        let lane = test_lane(&server, timing(10, 20, 20));
        let ch = test_channel(&lane, 1);
        ch.send(body.clone(), false, false).await.unwrap();
        assert!(wait_until(|| attempts.load(Ordering::SeqCst) == 1, ms(1000)).await);
        ch.send(key_body(b'n', 32), false, false).await.unwrap();
        let rec = tokio::spawn(ch.clone().recover());
        assert!(wait_until(|| attempts.load(Ordering::SeqCst) >= 4, ms(2000)).await);
        tokio::time::sleep(ms(80)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
        let st = ch.stats();
        // Оригинал всё ещё ждёт ответа; слоты повторов свободны.
        assert_eq!(st.pending, 1);
        assert_eq!(st.replay_pending, 0);
        rec.abort();
    }

    #[tokio::test]
    async fn recovery_does_not_wait_for_channel_or_lane_capacity() {
        let server = TestServer::new(handler(|_m, _b, r| async move { r.full(200, b"") }));
        for (channel_requests, lane_requests) in [(0usize, 64usize), (8, 0)] {
            let limits = H2Limits {
                channel_requests,
                lane_requests,
                ..test_limits()
            };
            let lane = test_lane(&server, limits);
            let ch = test_channel(&lane, 1);
            let body = Bytes::from(vec![b'k'; 40]);
            ch.st.lock().history.push(ReplayPacket {
                sent_at: Instant::now(),
                body: body.clone(),
                sequence: 0,
                attempts: 0,
                last_attempt: None,
                pending: None,
                originals: HashSet::new(),
                retired: false,
                reply_id: None,
            });
            let r = tokio::time::timeout(ms(100), ch.send(body, false, true)).await.unwrap();
            assert_eq!(r, Ok(false));
            assert!(ch.send_lock.try_lock().is_ok());
            assert!(!ch.st.lock().history[0].replayed());
            assert_eq!(ch.stats().requests, 0);
            assert_eq!(lane.inflight(), 0);
        }
    }

    #[tokio::test]
    async fn idle_channel_without_history_never_wakes_recovery() {
        let server = TestServer::new(handler(|_m, _b, r| async move { r.full(200, b"") }));
        let lane = test_lane(&server, test_limits());
        let ch = test_channel(&lane, 1);
        let rec = tokio::spawn(ch.clone().recover());
        tokio::time::sleep(ms(100)).await;
        assert_eq!(ch.stats().recovery_passes, 1);
        rec.abort();
    }
}

#[cfg(test)]
mod pool_tests {
    use super::test_support::*;
    use super::*;

    async fn balancer(domains: &[&str]) -> tokio::sync::MutexGuard<'static, ()> {
        let lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let list: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
        let mut b = crate::balancer::BALANCER.write();
        // update_domains_list пропускает тот же набор: сначала другой.
        b.update_domains_list(&["reset.invalid".to_string()]);
        b.update_domains_list(&list);
        lock
    }

    fn pool(server: &Arc<TestServer>, limits: H2Limits) -> H2Pool {
        H2Pool::with_connector(Arc::new(server.clone()), limits)
    }

    fn head_ok() -> Handler {
        handler(|_m, body, r| async move { r.full(if body.is_empty() { 501 } else { 200 }, &body) })
    }

    #[tokio::test]
    async fn first_open_goes_to_ws_and_prepares_lane_in_background() {
        let _g = balancer(&["example.org"]).await;
        let server = TestServer::new(head_ok());
        let pool = pool(&server, test_limits());
        let mut opened = Vec::new();
        for _ in 0..6 {
            opened.push(pool.try_open(4, "owned-test").unwrap());
        }
        assert!(opened.iter().all(|c| c.is_none()));
        assert!(wait_until(|| pool.lane_count() == 1 && !pool.setup_running(4), ms(2000)).await);
        assert_eq!(server.heads(), 1);
        let channels: Vec<Arc<Channel>> =
            (0..6).map(|_| pool.try_open(4, "owned-test").unwrap().unwrap()).collect();
        let ids: HashSet<u64> = channels.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), 6);
        assert!(channels.iter().all(|c| Arc::ptr_eq(c.lane(), &channels[0].lane)));
        assert_eq!(channels[0].lane().host, "kws4.example.org");
        assert_eq!(server.connects.load(Ordering::Relaxed), 1);
        pool.close().await;
        assert!(channels.iter().all(|c| c.is_closed()));
    }

    #[tokio::test]
    async fn closed_pool_cannot_open_new_channels() {
        let server = TestServer::new(head_ok());
        let pool = pool(&server, test_limits());
        pool.close().await;
        assert!(matches!(pool.try_open(4, "owned-test"), Err(H2Error::Closed(_))));
    }

    #[tokio::test]
    async fn unsupported_or_test_dc_never_preflights() {
        let _g = balancer(&["example.org"]).await;
        let server = TestServer::new(head_ok());
        let pool = pool(&server, test_limits());
        assert!(pool.try_open(10004, "owned-test").unwrap().is_none());
        assert!(pool.try_open(7, "owned-test").unwrap().is_none());
        tokio::time::sleep(ms(30)).await;
        assert_eq!(server.connects.load(Ordering::Relaxed), 0);
        assert!(!pool.setup_running(7));
    }

    #[tokio::test]
    async fn failing_preflight_stays_on_ws_with_growing_cooldown() {
        let _g = balancer(&["example.org"]).await;
        let server = TestServer::new(handler(|_m, _b, r| async move { r.full(404, b"") }));
        let limits = H2Limits {
            cooldown_initial: ms(60),
            cooldown_max: ms(1000),
            ..test_limits()
        };
        let pool = pool(&server, limits);
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| !pool.setup_running(4), ms(2000)).await);
        assert_eq!(server.heads(), 1);
        assert_eq!(pool.lane_count(), 0);
        // DC и домен в cooldown: новых preflight нет.
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(!pool.setup_running(4));
        tokio::time::sleep(ms(80)).await;
        // Через 60 мс — вторая попытка, после неё cooldown уже 120 мс.
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| server.heads() == 2 && !pool.setup_running(4), ms(2000)).await);
        tokio::time::sleep(ms(80)).await;
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(!pool.setup_running(4));
        assert_eq!(server.heads(), 2);
        // Смена сети сбрасывает cooldown.
        pool.reset().await;
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| server.heads() == 3, ms(2000)).await);
    }

    #[tokio::test]
    async fn hanging_setup_times_out_and_cleans_up_lane() {
        let _g = balancer(&["example.org"]).await;
        let server = TestServer::new(handler(|_m, _b, _r| async move { pending().await }));
        let limits = H2Limits {
            setup_timeout: ms(50),
            ..test_limits()
        };
        let pool = pool(&server, limits);
        let errors = STATS.h2_errors.load(Ordering::Relaxed);
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| !pool.setup_running(4), ms(2000)).await);
        assert!(STATS.h2_errors.load(Ordering::Relaxed) > errors);
        assert_eq!(pool.lane_count(), 0);
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(!pool.setup_running(4));
        assert_eq!(server.heads(), 1);
    }

    #[tokio::test]
    async fn unreachable_domain_falls_through_to_next_domain() {
        let _g = balancer(&["bad.example", "good.example"]).await;
        let server = TestServer::new(head_ok());
        server.refuse_hosts.lock().insert("kws2.bad.example".into());
        let pool = pool(&server, test_limits());
        assert!(pool.try_open(2, "owned-test").unwrap().is_none());
        assert!(wait_until(|| pool.lane_count() == 1 && !pool.setup_running(2), ms(2000)).await);
        let ch = pool.try_open(2, "owned-test").unwrap().unwrap();
        assert_eq!(ch.lane().host, "kws2.good.example");
        assert_eq!(
            crate::balancer::BALANCER.read().get_domains_for_dc(2)[0],
            "good.example"
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn idle_lane_closes_after_last_channel() {
        let _g = balancer(&["example.org"]).await;
        let server = TestServer::new(head_ok());
        let limits = H2Limits {
            lane_idle: ms(80),
            ..test_limits()
        };
        let pool = pool(&server, limits);
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| pool.lane_count() == 1, ms(2000)).await);
        let ch = pool.try_open(4, "owned-test").unwrap().unwrap();
        let lane = ch.lane().clone();
        tokio::time::sleep(ms(150)).await;
        assert!(!lane.is_closed(), "lane with a channel must stay open");
        ch.close().await;
        assert!(wait_until(|| lane.is_closed(), ms(1000)).await);
        assert_eq!(pool.lane_count(), 0);
    }

    #[tokio::test]
    async fn unused_lane_after_preflight_closes_by_idle_timer() {
        let _g = balancer(&["example.org"]).await;
        let server = TestServer::new(head_ok());
        let limits = H2Limits {
            lane_idle: ms(60),
            ..test_limits()
        };
        let pool = pool(&server, limits);
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| pool.lane_count() == 1, ms(2000)).await);
        assert!(wait_until(|| pool.lane_count() == 0, ms(1000)).await);
    }

    #[tokio::test]
    async fn reset_closes_lanes_and_reopens_on_demand() {
        let _g = balancer(&["example.org"]).await;
        let server = TestServer::new(head_ok());
        let pool = pool(&server, test_limits());
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| pool.lane_count() == 1, ms(2000)).await);
        let ch = pool.try_open(4, "owned-test").unwrap().unwrap();
        pool.reset().await;
        assert!(ch.is_closed());
        assert_eq!(pool.lane_count(), 0);
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| pool.lane_count() == 1, ms(2000)).await);
        assert_eq!(server.heads(), 2);
    }

    #[tokio::test]
    async fn reset_with_inflight_request_leaves_no_cooldown_for_new_network() {
        let _g = balancer(&["example.org"]).await;
        let server = TestServer::new(handler(|_m, body, r| async move {
            if !body.is_empty() {
                pending().await;
            }
            r.full(501, b"")
        }));
        let pool = pool(&server, test_limits());
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| pool.lane_count() == 1, ms(2000)).await);
        let ch = pool.try_open(4, "owned-test").unwrap().unwrap();
        let lane = ch.lane().clone();
        ch.send(Bytes::from(vec![b'q'; 40]), false, false).await.unwrap();
        assert!(wait_until(|| server.posts().len() == 1, ms(1000)).await);
        pool.reset().await;
        tokio::time::sleep(ms(30)).await;
        assert!(!lane.in_cooldown());
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(pool.setup_running(4));
    }

    #[tokio::test]
    async fn reset_during_preflight_discards_stale_lane() {
        let _g = balancer(&["example.org"]).await;
        let gate = CancellationToken::new();
        let g2 = gate.clone();
        let server = TestServer::new(handler(move |_m, _b, r| {
            let gate = g2.clone();
            async move {
                gate.cancelled().await;
                r.full(501, b"")
            }
        }));
        let pool = pool(&server, test_limits());
        assert!(pool.try_open(4, "owned-test").unwrap().is_none());
        assert!(wait_until(|| server.heads() == 1, ms(2000)).await);
        pool.reset().await;
        gate.cancel();
        tokio::time::sleep(ms(50)).await;
        assert_eq!(pool.lane_count(), 0);
    }
}

#[cfg(test)]
mod tls_tests {
    use super::test_support::*;
    use super::*;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    const CA_DER: &[u8] = include_bytes!("testdata/tls/ca.der");
    const LEAF_DER: &[u8] = include_bytes!("testdata/tls/leaf.der");
    const LEAF_KEY_DER: &[u8] = include_bytes!("testdata/tls/leaf.key.der");

    fn client_h2_config() -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(CA_DER.to_vec())).unwrap();
        crate::tls::build_verified_configs(
            Arc::new(roots),
            Arc::new(rustls::time_provider::DefaultTimeProvider),
        )
        .h2
    }

    /// Локальный TLS-сервер test.example; с `alpn_h2` — ещё и h2::server,
    /// отвечающий эхом на POST и 501 на HEAD.
    async fn tls_server(alpn_h2: bool) -> std::net::SocketAddr {
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(LEAF_DER.to_vec())],
            PrivateKeyDer::try_from(LEAF_KEY_DER.to_vec()).unwrap(),
        )
        .unwrap();
        if alpn_h2 {
            cfg.alpn_protocols = vec![b"h2".to_vec()];
        }
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    if !alpn_h2 {
                        tokio::time::sleep(ms(500)).await;
                        return;
                    }
                    let Ok(mut conn) = h2::server::handshake(tls).await else { return };
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        tokio::spawn(async move {
                            let head = req.method() == http::Method::HEAD;
                            let mut body = req.into_body();
                            let mut data = BytesMut::new();
                            while let Some(Ok(c)) = body.data().await {
                                let _ = body.flow_control().release_capacity(c.len());
                                data.extend_from_slice(&c);
                            }
                            let status = if head { 501 } else { 200 };
                            let resp = http::Response::builder().status(status).body(()).unwrap();
                            let mut s = respond.send_response(resp, data.is_empty()).unwrap();
                            if !data.is_empty() {
                                let _ = s.send_data(data.freeze(), true);
                            }
                        });
                    }
                });
            }
        });
        addr
    }

    struct LocalTls {
        addr: std::net::SocketAddr,
        cfg: Arc<rustls::ClientConfig>,
    }

    impl Connector for LocalTls {
        fn connect<'a>(&'a self, _host: &'a str) -> ConnectFuture<'a> {
            Box::pin(async move {
                let tcp = tokio::net::TcpStream::connect(self.addr)
                    .await
                    .map_err(|e| H2Error::Io(e.to_string()))?;
                tls_h2_handshake(tcp, "test.example", self.cfg.clone()).await
            })
        }
    }

    #[test]
    fn h2_config_offers_only_h2_and_ws_configs_offer_nothing() {
        assert_eq!(crate::tls::h2_client_config().alpn_protocols, vec![b"h2".to_vec()]);
        assert!(crate::tls::client_config(false).alpn_protocols.is_empty());
        assert!(crate::tls::client_config(true).alpn_protocols.is_empty());
    }

    #[tokio::test]
    async fn lane_works_over_verified_tls_with_alpn_h2() {
        let addr = tls_server(true).await;
        let lane = Lane::new(
            "kws4.example.org".into(),
            1,
            test_limits(),
            Arc::new(LocalTls { addr, cfg: client_h2_config() }),
            Arc::new(Cooldowns::new(Duration::from_secs(30), Duration::from_secs(1800))),
            Weak::new(),
        );
        assert_eq!(lane.preflight().await.unwrap(), 501);
        let reply = lane.post(Bytes::from(vec![b'x'; 40]), None, false).await.unwrap();
        assert_eq!(reply, vec![b'x'; 40]);
        assert_eq!(lane.tcp_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn server_without_h2_alpn_is_rejected() {
        let addr = tls_server(false).await;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let e = tls_h2_handshake(tcp, "test.example", client_h2_config()).await.err().unwrap();
        assert!(e.to_string().contains("did not negotiate h2"), "{}", e);
    }

    #[tokio::test]
    async fn untrusted_certificate_is_rejected() {
        let addr = tls_server(true).await;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Корни Mozilla: тестовый УЦ им неизвестен.
        let cfg = crate::tls::build_verified_configs(
            Arc::new(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            }),
            Arc::new(rustls::time_provider::DefaultTimeProvider),
        )
        .h2;
        let e = tls_h2_handshake(tcp, "test.example", cfg).await.err().unwrap();
        assert!(e.to_string().contains("TLS"), "{}", e);
    }
}
