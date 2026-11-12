use crate::cfproxy::*;
use crate::config::*;
use crate::crypto::*;
use crate::faketls;
use crate::ws::*;
use crate::{ldebug, linfo, lwarn};
use byteorder::{ByteOrder, LittleEndian};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Fronting flag — proxy/pool.py::_WsPool.try_fronting_first (начинается true)
// ---------------------------------------------------------------------------

static TRY_FRONTING_FIRST: AtomicBool = AtomicBool::new(true);

pub fn ws_pool_fronting_first() -> bool {
    TRY_FRONTING_FIRST.load(Ordering::Relaxed)
}

pub fn set_ws_pool_fronting_first(v: bool) {
    TRY_FRONTING_FIRST.store(v, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

pub fn resolve_configured_target(dc: i32, is_media: bool) -> Option<String> {
    let map = DC_OPT.read();
    if is_media {
        if let Some(t) = map.get(&(-dc)) {
            if !t.is_empty() {
                return Some(t.clone());
            }
        }
    }
    if let Some(t) = map.get(&dc) {
        if !t.is_empty() {
            return Some(t.clone());
        }
    }
    None
}

pub fn resolve_fallback_target(dc: i32, _is_media: bool, is_test: bool) -> String {
    if is_test {
        DC_TEST_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    } else {
        DC_DEFAULT_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    }
}

pub fn ws_domains(dc: i32, is_media: bool) -> Vec<String> {
    let mut effective_dc = dc;
    if let Some(o) = DC_OVERRIDES.get(&dc) {
        effective_dc = *o;
    }
    if is_media {
        vec![
            format!("kws{}-1.web.telegram.org", effective_dc),
            format!("kws{}.web.telegram.org", effective_dc),
        ]
    } else {
        vec![
            format!("kws{}.web.telegram.org", effective_dc),
            format!("kws{}-1.web.telegram.org", effective_dc),
        ]
    }
}

pub fn ws_path_for(is_test: bool) -> &'static str {
    if is_test {
        WS_PATH_TEST
    } else {
        WS_PATH
    }
}

pub fn media_tag(is_media: bool) -> &'static str {
    if is_media {
        " media"
    } else {
        ""
    }
}

pub fn is_media_int(b: bool) -> i32 {
    if b {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// WsPool — порт proxy/pool.py::_WsPool
// refilling-backoff (1s..3600s), rotation протухших, fronting-first.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DcSlot {
    pub dc: i32,
    pub is_media: i32,
}

pub struct PoolEntry {
    pub ws: RawWebSocket,
    pub created: f64, // monotonic, как time.monotonic() в оригинале
}

struct SlotState {
    queue: Mutex<VecDeque<PoolEntry>>,
    refilling: AtomicI32,
}

pub struct WsPool {
    slots: Mutex<HashMap<DcSlot, Arc<SlotState>>>,
    rotating: Mutex<HashSet<DcSlot>>,
    refill_failures: Mutex<HashMap<DcSlot, (u32, f64)>>,
    cancel_token: CancellationToken,
    // Поколение пула: reset() его увеличивает, и refill/rotate,
    // начатые до сброса (например, в старой сети), ничего не меняют.
    generation: AtomicU64,
    #[cfg(test)]
    connect_hook: parking_lot::Mutex<Option<WsConnectHook>>,
}

#[cfg(test)]
type WsConnectHook = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<RawWebSocket>> + Send>>
        + Send
        + Sync,
>;

impl WsPool {
    pub fn new(cancel_token: CancellationToken) -> WsPool {
        WsPool {
            slots: Mutex::new(HashMap::new()),
            rotating: Mutex::new(HashSet::new()),
            refill_failures: Mutex::new(HashMap::new()),
            cancel_token,
            generation: AtomicU64::new(0),
            #[cfg(test)]
            connect_hook: parking_lot::Mutex::new(None),
        }
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    async fn get_slot(&self, slot: DcSlot) -> Arc<SlotState> {
        let mut map = self.slots.lock().await;
        map.entry(slot)
            .or_insert_with(|| {
                Arc::new(SlotState {
                    queue: Mutex::new(VecDeque::with_capacity(16)),
                    refilling: AtomicI32::new(0),
                })
            })
            .clone()
    }

    pub async fn get(
        self: &Arc<Self>,
        dc: i32,
        is_media: bool,
        target_ip: String,
        domains: Vec<String>,
    ) -> Option<RawWebSocket> {
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
        };
        let state = self.get_slot(slot).await;
        let now = now_monotonic();

        let mut ws: Option<RawWebSocket> = None;
        {
            let mut q = state.queue.lock().await;
            while let Some(entry) = q.pop_front() {
                let age = now - entry.created;
                // _is_stale из 1636903: возраст, closed, EOF/ошибка/CLOSE.
                if age > WS_POOL_REUSE_MAX_AGE || entry.ws.is_stale() {
                    let e = entry;
                    tokio::spawn(async move {
                        e.ws.close().await;
                    });
                    continue;
                }
                STATS.pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "WS pool hit DC{}{} (age={:.1}s, left={})",
                    dc,
                    if is_media { "m" } else { "" },
                    age,
                    q.len()
                );
                ws = Some(entry.ws);
                break;
            }
            if ws.is_none() {
                STATS.pool_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        if ws.is_some() {
            self.report_success(dc, is_media).await;
        }
        self.schedule_refill(slot, target_ip, domains).await;
        ws
    }

    async fn schedule_refill(
        self: &Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
    ) {
        // Backoff как в оригинале: не раньше _refill_after.
        {
            let failures = self.refill_failures.lock().await;
            if let Some((_, after)) = failures.get(&slot) {
                if now_monotonic() < *after {
                    return;
                }
            }
        }
        let state = self.get_slot(slot).await;
        if state
            .refilling
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        // pool_size <= 0 — преконнект отключён (как pool_size=0 в оригинале).
        if POOL_SIZE.load(Ordering::Relaxed) <= 0 {
            state.refilling.store(0, Ordering::SeqCst);
            return;
        }
        let pool = self.clone();
        let gen = self.generation();
        spawn_refill_task(pool, slot, state, target_ip, domains, gen);
    }

    async fn refill(
        self: Arc<Self>,
        slot: DcSlot,
        state: Arc<SlotState>,
        target_ip: String,
        domains: Vec<String>,
        gen: u64,
    ) {
        let _guard = RefillGuard {
            state: state.clone(),
        };
        let cur_len = state.queue.lock().await.len();
        let pool_sz = POOL_SIZE.load(Ordering::Relaxed).max(0) as usize;
        if cur_len >= pool_sz || pool_sz == 0 {
            return;
        }
        let needed = pool_sz - cur_len;

        let mut handles = Vec::new();
        for _ in 0..needed {
            let target_ip = target_ip.clone();
            let domains = domains.clone();
            let cancel = self.cancel_token.clone();
            #[cfg(test)]
            let hook = self.connect_hook.lock().clone();
            handles.push(tokio::spawn(async move {
                #[cfg(test)]
                if let Some(hook) = hook {
                    return tokio::select! {
                        _ = cancel.cancelled() => None,
                        r = hook() => r,
                    };
                }
                tokio::select! {
                    _ = cancel.cancelled() => None,
                    r = connect_one_ws(&target_ip, &domains) => r,
                }
            }));
        }

        let mut connected = 0;
        for h in handles {
            if let Ok(Some(ws)) = h.await {
                if self.generation() != gen {
                    // Пул сброшен (смена сети), пока шло соединение.
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                    continue;
                }
                let now = now_monotonic();
                let mut q = state.queue.lock().await;
                if q.len() < 16 {
                    q.push_back(PoolEntry { ws, created: now });
                    connected += 1;
                } else {
                    drop(q);
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                }
            }
        }

        if self.generation() != gen {
            return;
        }
        if connected > 0 {
            self.report_success(slot.dc, slot.is_media != 0).await;
            // Успешный WS из пула снимает cooldown IP.
            ip_cooldown_record_success(&target_ip);
            self.schedule_rotation(slot, target_ip, domains).await;
        } else {
            // Экспоненциальный backoff 1s..3600s как в оригинале.
            let mut failures = self.refill_failures.lock().await;
            let count = failures.get(&slot).map(|(c, _)| *c).unwrap_or(0) + 1;
            let shift = (count - 1).min(12);
            let delay = (WS_POOL_REFILL_BACKOFF_INITIAL * (2u64.pow(shift) as f64))
                .min(WS_POOL_REFILL_BACKOFF_MAX);
            failures.insert(slot, (count, now_monotonic() + delay));
            drop(failures);
            linfo!(
                "WS pool refill failed for DC{}{}, retry in {:.0}s",
                slot.dc,
                if slot.is_media != 0 { "m" } else { "" },
                delay
            );
        }
        ldebug!(
            "WS pool refilled DC{}{}: {} ready",
            slot.dc,
            if slot.is_media != 0 { "m" } else { "" },
            state.queue.lock().await.len()
        );
    }

    pub async fn report_success(&self, dc: i32, is_media: bool) {
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
        };
        self.refill_failures.lock().await.remove(&slot);
    }

    async fn schedule_rotation(
        self: &Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
    ) {
        {
            let mut rotating = self.rotating.lock().await;
            if rotating.contains(&slot) {
                return;
            }
            rotating.insert(slot);
        }
        let pool = self.clone();
        let cancel = self.cancel_token.clone();
        let gen = self.generation();
        spawn_rotate_task(pool, slot, target_ip, domains, cancel, gen);
    }

    async fn rotate(
        self: Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
        cancel: CancellationToken,
        gen: u64,
    ) {
        loop {
            if self.generation() != gen {
                break;
            }
            // Спим до ближайшего протухания, но не реже CHECK_INTERVAL.
            let sleep_dur = {
                let map = self.slots.lock().await;
                match map.get(&slot) {
                    Some(state) => {
                        let q = state.queue.lock().await;
                        if q.is_empty() {
                            None
                        } else {
                            let now = now_monotonic();
                            let min_expires = q
                                .iter()
                                .map(|e| e.created + WS_POOL_REUSE_MAX_AGE)
                                .fold(f64::INFINITY, f64::min);
                            Some((min_expires - now).clamp(0.0, WS_POOL_CHECK_INTERVAL))
                        }
                    }
                    None => None,
                }
            };
            let sleep_dur = match sleep_dur {
                Some(d) => d,
                None => break,
            };
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs_f64(sleep_dur)) => {}
            }

            let now = now_monotonic();
            let expired_count: usize;
            let ready_count: usize;
            {
                let map = self.slots.lock().await;
                let state = match map.get(&slot) {
                    Some(s) => s.clone(),
                    None => break,
                };
                let mut q = state.queue.lock().await;
                let mut ready = VecDeque::with_capacity(q.len());
                let mut expired = Vec::new();
                while let Some(e) = q.pop_front() {
                    if now - e.created >= WS_POOL_REUSE_MAX_AGE || e.ws.is_stale() {
                        expired.push(e.ws);
                    } else {
                        ready.push_back(e);
                    }
                }
                expired_count = expired.len();
                *q = ready;
                ready_count = q.len();
                for ws in expired {
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                }
            }
            if expired_count > 0 {
                ldebug!(
                    "WS pool rotated DC{}{}: {} stale, {} ready",
                    slot.dc,
                    if slot.is_media != 0 { "m" } else { "" },
                    expired_count,
                    ready_count
                );
            }
            let pool_sz = POOL_SIZE.load(Ordering::Relaxed).max(0) as usize;
            if ready_count == 0 {
                break;
            }
            if ready_count < pool_sz {
                self.schedule_refill(slot, target_ip.clone(), domains.clone())
                    .await;
            }
        }
        // После reset() метка ротации принадлежит уже новому поколению.
        let mut rotating = self.rotating.lock().await;
        if self.generation() == gen {
            rotating.remove(&slot);
        }
    }

    pub async fn warmup(self: &Arc<Self>, dc_opt_map: &HashMap<i32, String>) {
        let mut ndcs = 0;
        for (dc, target_ip) in dc_opt_map {
            if target_ip.is_empty() {
                continue;
            }
            ndcs += 1;
            for is_media in [false, true] {
                let domains = ws_domains(*dc, is_media);
                let slot = DcSlot {
                    dc: *dc,
                    is_media: is_media_int(is_media),
                };
                self.schedule_refill(slot, target_ip.clone(), domains).await;
            }
        }
        linfo!("WS pool warmup started for {} DC(s)", ndcs);
    }

    pub async fn idle_count(&self) -> usize {
        let map = self.slots.lock().await;
        let mut count = 0;
        for s in map.values() {
            count += s.queue.lock().await.len();
        }
        count
    }

    pub async fn close_all(&self) {
        let map = self.slots.lock().await;
        for s in map.values() {
            let mut q = s.queue.lock().await;
            for e in q.drain(..) {
                tokio::spawn(async move {
                    e.ws.close().await;
                });
            }
        }
    }

    /// Полный сброс: простаивающие сокеты, бэкофф refill, метки ротации.
    /// Поколение +1, поэтому задачи, начатые до сброса, свои сокеты
    /// закрывают, а не кладут в пул.
    pub async fn reset(&self) {
        {
            let mut rotating = self.rotating.lock().await;
            self.generation.fetch_add(1, Ordering::SeqCst);
            rotating.clear();
        }
        self.close_all().await;
        self.slots.lock().await.clear();
        self.refill_failures.lock().await.clear();
        set_ws_pool_fronting_first(true);
    }
}

// RefillGuard снимает флаг refilling при выходе (аналог finally: discard).
struct RefillGuard {
    state: Arc<SlotState>,
}
impl Drop for RefillGuard {
    fn drop(&mut self) {
        self.state.refilling.store(0, Ordering::SeqCst);
    }
}

// Синхронные спавн-хелперы: разрывают цикл типов async-future
// (schedule_refill → refill → schedule_rotation → rotate → schedule_refill),
// о который спотыкается rustc (E0391). Sync-fn не вкладывает future одной
// async-функции в другую — внутри только JoinHandle.
fn spawn_refill_task(
    pool: Arc<WsPool>,
    slot: DcSlot,
    state: Arc<SlotState>,
    target_ip: String,
    domains: Vec<String>,
    gen: u64,
) {
    tokio::spawn(async move {
        pool.refill(slot, state, target_ip, domains, gen).await;
    });
}

fn spawn_rotate_task(
    pool: Arc<WsPool>,
    slot: DcSlot,
    target_ip: String,
    domains: Vec<String>,
    cancel: CancellationToken,
    gen: u64,
) {
    tokio::spawn(async move {
        pool.rotate(slot, target_ip, domains, cancel, gen).await;
    });
}

// ---------------------------------------------------------------------------
// CfWorkerPool — порт proxy/pool.py::_CfWorkerPool
// ---------------------------------------------------------------------------

pub struct CfWorkerEntry {
    pub ws: RawWebSocket,
    pub created: f64,
    pub worker_domain: String,
}

/// Тайминги пула CF worker. В проде — константы из config.rs, тесты
/// подставляют короткие значения (как десктопные тесты патчат атрибуты класса).
#[derive(Clone, Copy, Debug)]
pub struct CfWorkerPoolTimings {
    pub max_age: f64,
    pub check_interval: f64,
    pub backoff_initial: f64,
    pub backoff_max: f64,
    /// Android: пауза ротации, если пул DC не запрашивали столько секунд.
    pub idle_stop: f64,
}

impl Default for CfWorkerPoolTimings {
    fn default() -> Self {
        CfWorkerPoolTimings {
            max_age: CF_WORKER_POOL_MAX_AGE,
            check_interval: CF_WORKER_POOL_CHECK_INTERVAL,
            backoff_initial: CF_WORKER_REFILL_BACKOFF_INITIAL,
            backoff_max: CF_WORKER_REFILL_BACKOFF_MAX,
            idle_stop: CF_WORKER_ROTATION_IDLE_STOP,
        }
    }
}

// Минимальный сон ротации, чтобы граничные значения времени не дали busy-loop.
const CF_WORKER_MIN_SLEEP: f64 = 0.01;
// Сколько StopProxy ждёт завершения фоновых задач пула.
const CF_WORKER_CLOSE_WAIT: Duration = Duration::from_secs(2);

/// Состояние одного DC — аналог записей _idle/_refilling/_rotating/
/// _refill_failures/_refill_after десктопа, собранных в одну структуру.
struct CfWorkerSlot {
    bucket: VecDeque<CfWorkerEntry>,
    refilling: bool,
    rotating: bool,
    failures: u32,
    refill_after: f64,
    last_requested: f64,
}

impl CfWorkerSlot {
    fn new(now: f64) -> Self {
        CfWorkerSlot {
            bucket: VecDeque::new(),
            refilling: false,
            rotating: false,
            failures: 0,
            refill_after: 0.0,
            last_requested: now,
        }
    }
}

struct CfWorkerState {
    // Растёт при каждом reset(): задачи прошлого поколения не трогают новое.
    epoch: u64,
    slots: HashMap<i32, CfWorkerSlot>,
}

#[cfg(test)]
type CfConnectHook = Arc<
    dyn Fn(i32) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<(RawWebSocket, String)>> + Send>>
        + Send
        + Sync,
>;

pub struct CfWorkerPool {
    // Синхронный мьютекс: под ним нет await.
    state: parking_lot::Mutex<CfWorkerState>,
    exhausted_until: Mutex<HashMap<String, f64>>,
    timings: CfWorkerPoolTimings,
    // Дочерний токен корневого: отменяется и StopProxy, и close().
    cancel: CancellationToken,
    tasks: parking_lot::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    connect_hook: parking_lot::Mutex<Option<CfConnectHook>>,
    #[cfg(test)]
    connect_calls: std::sync::atomic::AtomicUsize,
}

#[derive(Clone, Copy)]
enum CfSlotFlag {
    Refilling,
    Rotating,
}

/// RAII-guard: снимает флаг refilling/rotating при любом выходе из задачи,
/// включая отмену (аналог `finally: self._refilling.pop(dc)` десктопа).
struct CfSlotFlagGuard {
    pool: Arc<CfWorkerPool>,
    dc: i32,
    epoch: u64,
    flag: CfSlotFlag,
}

impl Drop for CfSlotFlagGuard {
    fn drop(&mut self) {
        let mut st = self.pool.state.lock();
        if st.epoch != self.epoch {
            return;
        }
        if let Some(slot) = st.slots.get_mut(&self.dc) {
            match self.flag {
                CfSlotFlag::Refilling => slot.refilling = false,
                CfSlotFlag::Rotating => slot.rotating = false,
            }
        }
    }
}

/// Результат одного шага ротации (вынесен отдельно, чтобы тестировать без таймеров).
struct CfRotationTick {
    expired: Vec<RawWebSocket>,
    ready: usize,
    need_refill: bool,
    idle_stop: bool,
    wake_at: f64,
}

fn close_detached(sockets: Vec<RawWebSocket>) {
    for ws in sockets {
        tokio::spawn(async move {
            ws.close().await;
        });
    }
}

impl CfWorkerPool {
    pub fn new(cancel_token: CancellationToken) -> CfWorkerPool {
        Self::with_timings(cancel_token, CfWorkerPoolTimings::default())
    }

    pub fn with_timings(cancel_token: CancellationToken, timings: CfWorkerPoolTimings) -> CfWorkerPool {
        CfWorkerPool {
            state: parking_lot::Mutex::new(CfWorkerState {
                epoch: 0,
                slots: HashMap::new(),
            }),
            exhausted_until: Mutex::new(HashMap::new()),
            timings,
            cancel: cancel_token.child_token(),
            tasks: parking_lot::Mutex::new(Vec::new()),
            #[cfg(test)]
            connect_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            connect_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// min(pool_size, PER_DC_LIMIT); 0 — пул выключен.
    fn target_size() -> usize {
        CF_WORKER_PER_DC_LIMIT.min(POOL_SIZE.load(Ordering::Relaxed).max(0) as usize)
    }

    // _is_stale из 1636903: возраст, closed, EOF/ошибка/CLOSE от сервера.
    fn is_stale(&self, entry: &CfWorkerEntry, now: f64) -> bool {
        now - entry.created >= self.timings.max_age || entry.ws.is_stale()
    }

    fn spawn_tracked<F>(&self, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(fut);
        let mut tasks = self.tasks.lock();
        tasks.retain(|h| !h.is_finished());
        tasks.push(handle);
    }

    /// Готовый WS из пула или None. И при попадании, и при промахе
    /// заказывает пополнение (порт get() из 1636903).
    pub fn get(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: String,
        worker_domains: Vec<String>,
    ) -> Option<(RawWebSocket, String)> {
        if Self::target_size() == 0 || worker_domains.is_empty() {
            return None;
        }
        let now = now_monotonic();
        let mut stale = Vec::new();
        let (hit, left) = {
            let mut st = self.state.lock();
            let slot = st
                .slots
                .entry(dc)
                .or_insert_with(|| CfWorkerSlot::new(now));
            slot.last_requested = now;
            let mut hit = None;
            while let Some(entry) = slot.bucket.pop_front() {
                if self.is_stale(&entry, now) {
                    stale.push(entry.ws);
                    continue;
                }
                hit = Some(entry);
                break;
            }
            (hit, slot.bucket.len())
        };
        close_detached(stale);
        match &hit {
            Some(e) => {
                STATS.cf_pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "CF worker pool hit DC{} via {} (age={:.1}s, left={})",
                    dc,
                    e.worker_domain,
                    now - e.created,
                    left
                );
            }
            None => {
                STATS.cf_pool_misses.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.schedule_refill(dc, fallback_dst, worker_domains);
        hit.map(|e| (e.ws, e.worker_domain))
    }

    fn schedule_refill(self: &Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>) {
        if self.cancel.is_cancelled() || Self::target_size() == 0 || worker_domains.is_empty() {
            return;
        }
        self.schedule_rotation(dc, &fallback_dst, &worker_domains);
        let now = now_monotonic();
        let epoch = {
            let mut st = self.state.lock();
            let epoch = st.epoch;
            let slot = st
                .slots
                .entry(dc)
                .or_insert_with(|| CfWorkerSlot::new(now));
            if slot.refilling || now < slot.refill_after {
                return;
            }
            slot.refilling = true;
            epoch
        };
        let guard = CfSlotFlagGuard {
            pool: self.clone(),
            dc,
            epoch,
            flag: CfSlotFlag::Refilling,
        };
        let pool = self.clone();
        self.spawn_tracked(async move {
            let _guard = guard;
            pool.refill(dc, fallback_dst, worker_domains, epoch).await;
        });
    }

    async fn refill(self: Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>, epoch: u64) {
        let target = Self::target_size();
        let needed = {
            let st = self.state.lock();
            if st.epoch != epoch {
                return;
            }
            match st.slots.get(&dc) {
                Some(slot) => target.saturating_sub(slot.bucket.len()),
                None => return,
            }
        };
        if needed == 0 {
            return;
        }
        let mut connected = 0usize;
        for _ in 0..needed {
            let result = tokio::select! {
                _ = self.cancel.cancelled() => return,
                r = self.connect_one(worker_domains.clone(), fallback_dst.clone(), dc) => r,
            };
            let Some((ws, worker_domain)) = result else {
                break;
            };
            let now = now_monotonic();
            let rejected = {
                let mut st = self.state.lock();
                let current = st.epoch == epoch;
                match st.slots.get_mut(&dc) {
                    // Android: пока шло соединение, ротация могла уйти в паузу
                    // по простою — тогда сокет не держим.
                    Some(slot) if current && now - slot.last_requested < self.timings.idle_stop => {
                        slot.bucket.push_back(CfWorkerEntry {
                            ws,
                            created: now,
                            worker_domain,
                        });
                        None
                    }
                    _ => Some(ws),
                }
            };
            if let Some(ws) = rejected {
                ws.close().await;
                return;
            }
            connected += 1;
        }
        let now = now_monotonic();
        let (ready, retry_in) = {
            let mut st = self.state.lock();
            if st.epoch != epoch {
                return;
            }
            let Some(slot) = st.slots.get_mut(&dc) else {
                return;
            };
            let retry_in = if connected > 0 {
                slot.failures = 0;
                slot.refill_after = 0.0;
                None
            } else {
                slot.failures = slot.failures.saturating_add(1);
                let delay = backoff_delay(
                    slot.failures,
                    self.timings.backoff_initial,
                    self.timings.backoff_max,
                    POOL_BACKOFF_MAX_SHIFT,
                );
                slot.refill_after = now + delay;
                Some(delay)
            };
            (slot.bucket.len(), retry_in)
        };
        if let Some(delay) = retry_in {
            linfo!("CF worker pool refill failed for DC{}, retry in {:.0}s", dc, delay);
        }
        ldebug!("CF worker pool refilled DC{}: {} ready", dc, ready);
    }

    fn schedule_rotation(self: &Arc<Self>, dc: i32, fallback_dst: &str, worker_domains: &[String]) {
        if self.cancel.is_cancelled() {
            return;
        }
        let now = now_monotonic();
        let epoch = {
            let mut st = self.state.lock();
            let epoch = st.epoch;
            let slot = st
                .slots
                .entry(dc)
                .or_insert_with(|| CfWorkerSlot::new(now));
            if slot.rotating {
                return;
            }
            slot.rotating = true;
            epoch
        };
        let guard = CfSlotFlagGuard {
            pool: self.clone(),
            dc,
            epoch,
            flag: CfSlotFlag::Rotating,
        };
        let pool = self.clone();
        let fallback_dst = fallback_dst.to_string();
        let worker_domains = worker_domains.to_vec();
        self.spawn_tracked(async move {
            let _guard = guard;
            pool.rotate(dc, fallback_dst, worker_domains, epoch).await;
        });
    }

    fn rotation_tick(&self, dc: i32, epoch: u64, now: f64) -> Option<CfRotationTick> {
        let target = Self::target_size();
        let t = self.timings;
        let mut st = self.state.lock();
        if st.epoch != epoch {
            return None;
        }
        let slot = st.slots.get_mut(&dc)?;
        if now - slot.last_requested >= t.idle_stop {
            // Android: пул давно не нужен — закрываем его и не будим CPU.
            let expired = slot.bucket.drain(..).map(|e| e.ws).collect();
            return Some(CfRotationTick {
                expired,
                ready: 0,
                need_refill: false,
                idle_stop: true,
                wake_at: now,
            });
        }
        let mut expired = Vec::new();
        let mut ready = VecDeque::with_capacity(slot.bucket.len());
        while let Some(entry) = slot.bucket.pop_front() {
            if self.is_stale(&entry, now) {
                expired.push(entry.ws);
            } else {
                ready.push_back(entry);
            }
        }
        slot.bucket = ready;
        let mut wake_at = now + t.check_interval;
        for entry in &slot.bucket {
            wake_at = wake_at.min(entry.created + t.max_age);
        }
        if !slot.refilling && slot.refill_after > now {
            wake_at = wake_at.min(slot.refill_after);
        }
        wake_at = wake_at.min(slot.last_requested + t.idle_stop);
        Some(CfRotationTick {
            expired,
            ready: slot.bucket.len(),
            need_refill: slot.bucket.len() < target,
            idle_stop: false,
            wake_at,
        })
    }

    async fn rotate(self: Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>, epoch: u64) {
        loop {
            if self.cancel.is_cancelled() || Self::target_size() == 0 {
                return;
            }
            let Some(tick) = self.rotation_tick(dc, epoch, now_monotonic()) else {
                return;
            };
            let expired = tick.expired.len();
            close_detached(tick.expired);
            if tick.idle_stop {
                ldebug!(
                    "CF worker pool DC{}: not requested for {:.0}s, rotation paused, {} closed",
                    dc,
                    self.timings.idle_stop,
                    expired
                );
                return;
            }
            if expired > 0 {
                ldebug!(
                    "CF worker pool rotated DC{}: {} stale, {} ready",
                    dc,
                    expired,
                    tick.ready
                );
            }
            if tick.need_refill {
                self.schedule_refill(dc, fallback_dst.clone(), worker_domains.clone());
            }
            let sleep_for = (tick.wake_at - now_monotonic()).max(CF_WORKER_MIN_SLEEP);
            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs_f64(sleep_for)) => {}
            }
        }
    }

    async fn connect_one(
        &self,
        worker_domains: Vec<String>,
        fallback_dst: String,
        dc: i32,
    ) -> Option<(RawWebSocket, String)> {
        #[cfg(test)]
        {
            self.connect_calls.fetch_add(1, Ordering::SeqCst);
            let hook = self.connect_hook.lock().clone();
            if let Some(hook) = hook {
                return hook(dc).await;
            }
        }
        let secure = cf_use_tls();
        let query = format!("dst={}&dc={}", fallback_dst, dc);
        let path = format!("/apiws?{}", query);
        for worker_domain in self.available_domains(worker_domains).await {
            match ws_connect_full_opts(&worker_domain, &worker_domain, &path, 8.0, None, secure)
                .await
            {
                Ok(ws) => return Some((ws, worker_domain)),
                Err(exc) => {
                    ldebug!(
                        "CF worker pool connect DC{} via {} for {} failed: {}",
                        dc,
                        worker_domain,
                        fallback_dst,
                        exc.compact()
                    );
                    self.report_failure(&worker_domain, &exc).await;
                }
            }
        }
        None
    }

    pub async fn available_domains(&self, worker_domains: Vec<String>) -> Vec<String> {
        let now = now_unix_f64();
        let mut exhausted = self.exhausted_until.lock().await;
        let mut domains = Vec::new();
        let mut seen = HashSet::new();
        for domain in worker_domains {
            if !seen.insert(domain.clone()) {
                continue;
            }
            if let Some(until) = exhausted.get(&domain) {
                if *until > now {
                    continue;
                }
            }
            exhausted.remove(&domain);
            domains.push(domain);
        }
        drop(exhausted);
        // random.shuffle как в оригинале.
        {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            domains.shuffle(&mut rng);
        }
        domains
    }

    pub async fn report_failure(&self, _worker_domain: &str, _exc: &WsError) {
        // TODO: picks up 429/daily-limit handling — как в оригинале пока no-op.
    }

    pub async fn warmup(self: &Arc<Self>, dc_opt_map: &HashMap<i32, String>) {
        let worker_domains = CF_WORKER_DOMAINS.read().clone();
        if Self::target_size() == 0 || worker_domains.is_empty() {
            return;
        }
        // CF worker греем только для DC, которых НЕТ в прямых редиректах.
        let fallbacks: Vec<(i32, String)> = DC_DEFAULT_IPS
            .iter()
            .filter(|(dc, _)| !dc_opt_map.contains_key(dc))
            .map(|(dc, ip)| (*dc, ip.to_string()))
            .collect();
        if fallbacks.is_empty() {
            return;
        }
        for (dc, fallback_dst) in &fallbacks {
            self.schedule_refill(*dc, fallback_dst.clone(), worker_domains.clone());
        }
        linfo!("CF worker pool warmup started for {} DC(s)", fallbacks.len());
    }

    fn take_all(&self, bump_epoch: bool) -> Vec<RawWebSocket> {
        let mut st = self.state.lock();
        if bump_epoch {
            st.epoch += 1;
        }
        let sockets = st
            .slots
            .values_mut()
            .flat_map(|slot| slot.bucket.drain(..).map(|e| e.ws))
            .collect();
        if bump_epoch {
            st.slots.clear();
        }
        sockets
    }

    /// Закрывает простаивающие соединения, состояние бэкоффа сохраняется.
    pub async fn close_all(&self) {
        close_detached(self.take_all(false));
    }

    /// Полный сброс: соединения, бэкофф, флаги. Задачи прошлого поколения
    /// после этого ничего не меняют (epoch).
    pub async fn reset(&self) {
        close_detached(self.take_all(true));
        self.exhausted_until.lock().await.clear();
    }

    /// Остановка: отмена фоновых задач, ожидание их завершения, закрытие
    /// всех соединений (аналог _CfWorkerPool.close() из c317406/1636903).
    pub async fn close(&self) {
        self.cancel.cancel();
        let handles: Vec<_> = std::mem::take(&mut *self.tasks.lock());
        let _ = tokio::time::timeout(CF_WORKER_CLOSE_WAIT, async {
            for handle in handles {
                let _ = handle.await;
            }
        })
        .await;
        let closing: Vec<_> = self
            .take_all(true)
            .into_iter()
            .map(|ws| tokio::spawn(async move { ws.close().await }))
            .collect();
        let _ = tokio::time::timeout(CF_WORKER_CLOSE_WAIT, async {
            for handle in closing {
                let _ = handle.await;
            }
        })
        .await;
        self.exhausted_until.lock().await.clear();
    }
}

// ---------------------------------------------------------------------------
// Shared pools (WS + CF worker) — один Arc на соединение.
// ---------------------------------------------------------------------------

pub struct ProxyPools {
    pub ws: Arc<WsPool>,
    pub cf_worker: Arc<CfWorkerPool>,
    cancel: CancellationToken,
    // Последнее событие сети, ожидающее применения после дебаунса.
    network_pending: parking_lot::Mutex<Option<(i32, i32)>>,
    network_debounce: Duration,
}

/// `transport` из OnNetworkChanged: 0 неизвестно, 1 Wi-Fi, 2 сотовая, 3 прочее.
pub fn network_transport_name(transport: i32) -> &'static str {
    match transport {
        1 => "wifi",
        2 => "cellular",
        3 => "other",
        _ => "unknown",
    }
}

impl ProxyPools {
    pub fn new(cancel_token: CancellationToken) -> Self {
        Self::with_network_debounce(
            cancel_token,
            Duration::from_secs_f64(NETWORK_CHANGE_DEBOUNCE),
        )
    }

    pub fn with_network_debounce(cancel_token: CancellationToken, debounce: Duration) -> Self {
        ProxyPools {
            ws: Arc::new(WsPool::new(cancel_token.clone())),
            cf_worker: Arc::new(CfWorkerPool::new(cancel_token.clone())),
            cancel: cancel_token,
            network_pending: parking_lot::Mutex::new(None),
            network_debounce: debounce,
        }
    }

    /// Сигнал Android о смене сети по умолчанию (`state` 1) или её
    /// потере (`state` 0). Не блокирует: ставит отложенную задачу и сразу
    /// возвращается. События в окне дебаунса сливаются, применяется
    /// последнее. Вызывать внутри tokio-рантайма.
    pub fn on_network_changed(self: &Arc<Self>, state: i32, transport: i32) {
        if self.cancel.is_cancelled() {
            return;
        }
        {
            let mut pending = self.network_pending.lock();
            let scheduled = pending.is_some();
            *pending = Some((state, transport));
            if scheduled {
                ldebug!(
                    "Network change merged: state={} transport={}",
                    state,
                    network_transport_name(transport)
                );
                return;
            }
        }
        let pools = self.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = pools.cancel.cancelled() => {
                    pools.network_pending.lock().take();
                    return;
                }
                _ = tokio::time::sleep(pools.network_debounce) => {}
            }
            let Some((state, transport)) = pools.network_pending.lock().take() else {
                return;
            };
            pools.apply_network_change(state, transport).await;
        });
    }

    /// Сброс состояния, привязанного к старой сети. WS_BLACKLIST и активные
    /// сессии не трогаются.
    async fn apply_network_change(&self, state: i32, transport: i32) {
        if self.cancel.is_cancelled() {
            return;
        }
        let idle = self.ws.idle_count().await;
        linfo!(
            "Network {} ({}): resetting pools ({} idle WS), cooldowns and backoffs",
            if state != 0 { "changed" } else { "lost" },
            network_transport_name(transport),
            idle
        );
        self.ws.reset().await; // + TRY_FRONTING_FIRST = true
        self.cf_worker.reset().await;
        IP_FAIL_UNTIL.write().clear();
        DC_FAIL_UNTIL.write().clear();
        reset_tcp_backoff();
        reset_port_memory();
        clear_cfproxy_429_cooldowns();
        set_ws_pool_fronting_first(true);
        if state != 0 && !self.cancel.is_cancelled() {
            let dc_opt_map = DC_OPT.read().clone();
            self.warmup(&dc_opt_map).await;
        }
    }

    pub async fn warmup(&self, dc_opt_map: &HashMap<i32, String>) {
        self.ws.warmup(dc_opt_map).await;
        self.cf_worker.warmup(dc_opt_map).await;
    }

    pub async fn close_all(&self) {
        self.ws.close_all().await;
        self.cf_worker.close().await;
    }

    pub async fn reset(&self) {
        self.ws.reset().await;
        self.cf_worker.reset().await;
    }
}

// ---------------------------------------------------------------------------
// HTTP transport detection
// ---------------------------------------------------------------------------

pub fn is_http_transport(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    &data[..4] == b"POST"
        || &data[..3] == b"GET"
        || &data[..4] == b"HEAD"
        || (data.len() >= 7 && &data[..7] == b"OPTIONS")
}

// ---------------------------------------------------------------------------
// Bridge WS — generic core + TcpStream wrapper.
// Сессионная статистика как в bridge_ws_reencrypt оригинала.
// ---------------------------------------------------------------------------

pub async fn bridge_ws<R, W>(
    conn_read: R,
    conn_write: W,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    mut splitter: Option<MsgSplitter>,
    mut clt_dec: TrackedStream,
    mut clt_enc: TrackedStream,
    mut tg_enc: TrackedStream,
    mut tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let dc_tag = format!("DC{}{}", dc, if is_media { "m" } else { "" });
    let ws = Arc::new(ws);
    let last_activity = Arc::new(Mutex::new(std::time::Instant::now()));
    // Сигнал «сессия закончена» между задачами. CancellationToken, а не
    // Notify::notify_waiters: отмена «липкая» и не теряется, если вторая
    // задача ещё не дошла до ожидания (иначе после EOF клиента сессия
    // висела до BRIDGE_READ_TIMEOUT). Дочерний токен: отмена сессии не
    // трогает родительский, а StopProxy отменяет и его.
    let cancel = cancel_token.child_token();
    let start = now_monotonic();

    let mut conn_read = conn_read;
    let mut conn_write = conn_write;

    // ping keepalive (мобильное улучшение поверх оригинала).
    let ws_ping = ws.clone();
    let la_ping = last_activity.clone();
    let cancel_ping = cancel.clone();
    let cancel_token_ping = cancel_token.clone();
    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(BRIDGE_PING_INTERVAL);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel_token_ping.cancelled() => return,
                _ = cancel_ping.cancelled() => return,
                _ = interval.tick() => {
                    let idle = la_ping.lock().await.elapsed();
                    if idle > BRIDGE_PING_INTERVAL {
                        if ws_ping.send_ping().await.is_err() {
                            cancel_ping.cancel();
                            return;
                        }
                    }
                }
            }
        }
    });

    // up: client -> ws
    let ws_up = ws.clone();
    let la_up = last_activity.clone();
    let cancel_up = cancel.clone();
    let cancel_token_up = cancel_token.clone();
    let up_bytes = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let up_packets = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let up_bytes_c = up_bytes.clone();
    let up_packets_c = up_packets.clone();
    let close_reason_up = Arc::new(Mutex::new(String::new()));
    let close_reason_up_c = close_reason_up.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; WS_BRIDGE_CHUNK_SIZE];
        // Открытый текст для MsgSplitter: копия чанка между clt_dec и
        // tg_enc вместо второго AES-CTR внутри splitter. Буфер переиспользуется.
        let mut plain: Vec<u8> = if splitter.is_some() {
            Vec::with_capacity(WS_BRIDGE_CHUNK_SIZE)
        } else {
            Vec::new()
        };
        loop {
            let read_res = tokio::select! {
                _ = cancel_token_up.cancelled() => break,
                _ = cancel_up.cancelled() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, conn_read.read(&mut buf)) => r,
            };
            let n = match read_res {
                Ok(Ok(0)) => {
                    // EOF: flush splitter tail
                    if let Some(sp) = splitter.as_mut() {
                        let tail = sp.flush();
                        if !tail.is_empty() {
                            let r = if tail.len() > 1 {
                                ws_up.send_batch(&tail).await
                            } else {
                                ws_up.send(&tail[0]).await
                            };
                            if r.is_err() {
                                *close_reason_up_c.lock().await =
                                    "upstream: send_failed".to_string();
                                break;
                            }
                        }
                    }
                    break;
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    *close_reason_up_c.lock().await =
                        format!("client: {}", e.kind());
                    break;
                }
                Err(_) => {
                    *close_reason_up_c.lock().await = "client: timeout".to_string();
                    break;
                }
            };

            let chunk = &mut buf[..n];
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            up_bytes_c.fetch_add(n as i64, Ordering::Relaxed);
            up_packets_c.fetch_add(1, Ordering::Relaxed);
            *la_up.lock().await = std::time::Instant::now();

            clt_dec.xor(chunk);
            if splitter.is_some() {
                plain.clear();
                plain.extend_from_slice(chunk);
            }
            tg_enc.xor(chunk);

            let send_err = {
                if let Some(sp) = splitter.as_mut() {
                    let parts = sp.split(chunk, &plain);
                    if parts.len() > 1 {
                        ws_up.send_batch(&parts).await.is_err()
                    } else if parts.len() == 1 {
                        ws_up.send(&parts[0]).await.is_err()
                    } else {
                        false
                    }
                } else {
                    ws_up.send(chunk).await.is_err()
                }
            };
            if send_err {
                *close_reason_up_c.lock().await = "upstream: send_failed".to_string();
                break;
            }
        }
        cancel_up.cancel();
    });

    // down: ws -> client
    let ws_down = ws.clone();
    let la_down = last_activity.clone();
    let cancel_down = cancel.clone();
    let cancel_token_down = cancel_token.clone();
    let down_bytes = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let down_packets = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let down_bytes_c = down_bytes.clone();
    let down_packets_c = down_packets.clone();
    let close_reason_down = Arc::new(Mutex::new(String::new()));
    let close_reason_down_c = close_reason_down.clone();
    let down_task = tokio::spawn(async move {
        loop {
            let recv_res = tokio::select! {
                _ = cancel_token_down.cancelled() => break,
                _ = cancel_down.cancelled() => break,
                r = ws_down.recv_with_timeout(BRIDGE_READ_TIMEOUT) => r,
            };
            let mut data = match recv_res {
                Ok(d) => d,
                Err(WsError::Timeout) => {
                    *close_reason_down_c.lock().await =
                        "upstream: timeout".to_string();
                    break;
                }
                Err(_) => {
                    let cur = close_reason_down_c.lock().await.clone();
                    if cur.is_empty() {
                        *close_reason_down_c.lock().await =
                            "upstream: ws_close".to_string();
                    }
                    break;
                }
            };
            let n = data.len();
            STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
            down_bytes_c.fetch_add(n as i64, Ordering::Relaxed);
            down_packets_c.fetch_add(1, Ordering::Relaxed);
            *la_down.lock().await = std::time::Instant::now();

            tg_dec.xor(&mut data);
            clt_enc.xor(&mut data);
            if conn_write.write_all(&data).await.is_err() {
                *close_reason_down_c.lock().await = "client: write_failed".to_string();
                break;
            }
        }
        cancel_down.cancel();
    });

    let _ = up_task.await;
    let _ = down_task.await;
    cancel.cancel();
    ping_task.abort();

    let close_reason = {
        let up_r = close_reason_up.lock().await.clone();
        let down_r = close_reason_down.lock().await.clone();
        if !down_r.is_empty() {
            down_r
        } else if !up_r.is_empty() {
            up_r
        } else {
            "normal".to_string()
        }
    };
    let elapsed = now_monotonic() - start;
    linfo!(
        "[{}] {} WS session closed ({}): ^{}{} ({} pkts) v{}{} ({} pkts) in {:.1}s",
        label,
        dc_tag,
        close_reason,
        human_bytes(up_bytes.load(Ordering::Relaxed)),
        "",
        up_packets.load(Ordering::Relaxed),
        human_bytes(down_bytes.load(Ordering::Relaxed)),
        "",
        down_packets.load(Ordering::Relaxed),
        elapsed
    );

    ws.close().await;
}

/// Совместимость: bridge по TcpStream (разрезаем внутри).
pub async fn bridge_ws_stream(
    conn: TcpStream,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (conn_read, conn_write) = tokio::io::split(conn);
    bridge_ws(
        conn_read,
        conn_write,
        ws,
        label,
        dc,
        is_media,
        splitter,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Bridge TCP — generic core + wrapper.
// ---------------------------------------------------------------------------

pub async fn bridge_tcp<CR, CW>(
    mut c_read: CR,
    mut c_write: CW,
    mut remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) where
    CR: AsyncReadExt + Unpin + Send + 'static,
    CW: AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut r_read, mut r_write) = remote.split();

    let clt_dec = Arc::new(Mutex::new(clt_dec));
    let clt_enc = Arc::new(Mutex::new(clt_enc));
    let tg_enc = Arc::new(Mutex::new(tg_enc));
    let tg_dec = Arc::new(Mutex::new(tg_dec));

    // Сигнал «сессия закончена» между задачами. CancellationToken, а не
    // Notify::notify_waiters: отмена «липкая» и не теряется, если вторая
    // задача ещё не дошла до ожидания (иначе после EOF клиента сессия
    // висела до BRIDGE_READ_TIMEOUT). Дочерний токен: отмена сессии не
    // трогает родительский, а StopProxy отменяет и его.
    let cancel = cancel_token.child_token();

    let cancel_up = cancel.clone();
    let cancel_token_up = cancel_token.clone();
    let clt_dec_up = clt_dec.clone();
    let tg_enc_up = tg_enc.clone();
    let up = async move {
        let mut buf = vec![0u8; 131072];
        loop {
            let n = tokio::select! {
                _ = cancel_token_up.cancelled() => break,
                _ = cancel_up.cancelled() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, c_read.read(&mut buf)) => match r {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                },
            };
            let chunk = &mut buf[..n];
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            clt_dec_up.lock().await.xor(chunk);
            tg_enc_up.lock().await.xor(chunk);
            if r_write.write_all(chunk).await.is_err() {
                break;
            }
        }
        cancel_up.cancel();
    };

    let cancel_down = cancel.clone();
    let cancel_token_down = cancel_token.clone();
    let tg_dec_down = tg_dec.clone();
    let clt_enc_down = clt_enc.clone();
    let down = async move {
        let mut buf = vec![0u8; 131072];
        loop {
            let n = tokio::select! {
                _ = cancel_token_down.cancelled() => break,
                _ = cancel_down.cancelled() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, r_read.read(&mut buf)) => match r {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                },
            };
            let chunk = &mut buf[..n];
            STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
            tg_dec_down.lock().await.xor(chunk);
            clt_enc_down.lock().await.xor(chunk);
            if c_write.write_all(chunk).await.is_err() {
                break;
            }
        }
        cancel_down.cancel();
    };

    tokio::join!(up, down);
    let _ = (clt_dec, clt_enc, tg_enc, tg_dec);
}

pub async fn bridge_tcp_stream(
    client: TcpStream,
    remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (c_read, c_write) = tokio::io::split(client);
    bridge_tcp(
        c_read,
        c_write,
        remote,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// TCP fallback — порт bridge._tcp_fallback
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Бэкофф TCP fallback — порт proxy/bridge.py (_tcp_failures, _tcp_retry_after,
// _tcp_connecting из 50c980e). Ключ — (dst, port).
// ---------------------------------------------------------------------------

pub type TcpBackoffKey = (String, u16);

#[derive(Default)]
struct TcpBackoffState {
    // key -> (подряд неудач, monotonic-время, раньше которого не пробовать)
    failures: HashMap<TcpBackoffKey, (u32, f64)>,
    connecting: HashSet<TcpBackoffKey>,
}

pub struct TcpBackoff {
    state: parking_lot::Mutex<TcpBackoffState>,
}

/// Снимает отметку «идёт попытка» при выходе из области видимости,
/// в том числе при отмене задачи посреди connect.
pub struct TcpAttemptGuard<'a> {
    backoff: &'a TcpBackoff,
    key: TcpBackoffKey,
}

impl Drop for TcpAttemptGuard<'_> {
    fn drop(&mut self) {
        self.backoff.state.lock().connecting.remove(&self.key);
    }
}

impl TcpBackoff {
    pub fn new() -> Self {
        TcpBackoff {
            state: parking_lot::Mutex::new(TcpBackoffState::default()),
        }
    }

    /// `None`, если по ключу уже идёт попытка или не истёк бэкофф.
    pub fn try_begin(&self, key: &TcpBackoffKey, now: f64) -> Option<TcpAttemptGuard<'_>> {
        let mut st = self.state.lock();
        if st.connecting.contains(key) {
            return None;
        }
        if let Some((_, retry_after)) = st.failures.get(key) {
            if now < *retry_after {
                return None;
            }
        }
        st.connecting.insert(key.clone());
        Some(TcpAttemptGuard {
            backoff: self,
            key: key.clone(),
        })
    }

    /// Фиксирует неудачу и возвращает задержку до следующей попытки.
    pub fn record_failure(&self, key: &TcpBackoffKey, now: f64) -> f64 {
        let mut st = self.state.lock();
        let failures = st.failures.get(key).map(|(n, _)| *n).unwrap_or(0) + 1;
        let delay = backoff_delay(
            failures,
            TCP_BACKOFF_INITIAL,
            TCP_BACKOFF_MAX,
            TCP_BACKOFF_MAX_SHIFT,
        );
        st.failures.insert(key.clone(), (failures, now + delay));
        delay
    }

    pub fn record_success(&self, key: &TcpBackoffKey) {
        self.state.lock().failures.remove(key);
    }

    pub fn clear(&self) {
        let mut st = self.state.lock();
        st.failures.clear();
        st.connecting.clear();
    }

    #[cfg(test)]
    fn failures(&self, key: &TcpBackoffKey) -> Option<(u32, f64)> {
        self.state.lock().failures.get(key).copied()
    }

    #[cfg(test)]
    fn is_connecting(&self, key: &TcpBackoffKey) -> bool {
        self.state.lock().connecting.contains(key)
    }
}

impl Default for TcpBackoff {
    fn default() -> Self {
        Self::new()
    }
}

pub static TCP_BACKOFF: once_cell::sync::Lazy<TcpBackoff> =
    once_cell::sync::Lazy::new(TcpBackoff::new);

/// Сброс бэкоффа TCP fallback (аналог reset_tcp_backoff() десктопа).
pub fn reset_tcp_backoff() {
    TCP_BACKOFF.clear();
}

// ---------------------------------------------------------------------------
// Порт 443 → 80 для прямого WS к DC и TCP fallback, с запоминанием
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PortRoute {
    DirectWs,
    TcpFallback,
}

/// Порт, на котором маршрут к цели последний раз заработал. Живёт до конца
/// сессии прокси; сбрасывается в OnNetworkChanged и StopProxy.
static WORKING_PORT: once_cell::sync::Lazy<parking_lot::Mutex<HashMap<(PortRoute, String), u16>>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(HashMap::new()));

/// Порядок портов для маршрута: всегда сначала 443, как на десктопе; в
/// режиме «порт 80» затем 80. Запомненный рабочий порт идёт первым, чтобы не
/// платить таймаутом на каждом соединении.
pub fn port_order(route: PortRoute, target: &str) -> Vec<u16> {
    let mut ports = vec![PORT_TLS];
    if port80_fallback_enabled() {
        ports.push(PORT_PLAIN);
    }
    if let Some(&p) = WORKING_PORT.lock().get(&(route, target.to_string())) {
        if let Some(i) = ports.iter().position(|&x| x == p) {
            ports.remove(i);
            ports.insert(0, p);
        }
    }
    ports
}

pub fn remember_port(route: PortRoute, target: &str, port: u16) {
    WORKING_PORT.lock().insert((route, target.to_string()), port);
}

pub fn reset_port_memory() {
    WORKING_PORT.lock().clear();
}

/// Похоже ли на блокировку порта: таймаут или сброс/отказ соединения.
/// Остальные ошибки (нет сети, ответ сервера) на другой порт не переводят.
fn is_port_blocking_io_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        TimedOut | ConnectionReset | ConnectionRefused | ConnectionAborted | BrokenPipe | UnexpectedEof
    )
}

fn is_port_blocking_ws_error(e: &WsError) -> bool {
    match e {
        WsError::Timeout => true,
        WsError::Io(io) => is_port_blocking_io_error(io),
        _ => false,
    }
}

/// Прямой WS к DC: wss на 443, в режиме «порт 80» — затем ws на 80, если 443
/// заблокирован. Ответ сервера (в т.ч. 302) возвращается сразу, без смены
/// порта. Рабочий порт запоминается для `target`.
pub async fn connect_direct_ws_ports(
    label: &str,
    target: &str,
    domain: &str,
    path: &str,
    timeout: f64,
) -> Result<RawWebSocket, WsError> {
    let ports = port_order(PortRoute::DirectWs, target);
    let mut last_err = None;
    for (i, &port) in ports.iter().enumerate() {
        match ws_connect_full_opts(target, domain, path, timeout, None, port == PORT_TLS).await {
            Ok(ws) => {
                if i > 0 || port != PORT_TLS {
                    linfo!(
                        "[{}] WS to {} via {}:{} ({})",
                        label,
                        domain,
                        target,
                        port,
                        if port == PORT_TLS { "wss" } else { "ws, без TLS" }
                    );
                }
                remember_port(PortRoute::DirectWs, target, port);
                return Ok(ws);
            }
            Err(e) => {
                if i + 1 < ports.len() && is_port_blocking_ws_error(&e) {
                    ldebug!(
                        "[{}] WS to {} via {}:{} failed ({}), trying port {}",
                        label,
                        domain,
                        target,
                        port,
                        e.compact(),
                        ports[i + 1]
                    );
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err.unwrap_or(WsError::Other("no ports".to_string())))
}

enum TcpAttempt {
    Connected(TcpStream),
    Skipped,
    Failed { blocked: bool },
}

/// Одна попытка TCP fallback на `dst:port` с бэкоффом: соединение и
/// отправка relay_init.
async fn tcp_fallback_attempt(dst: &str, port: u16, init: &[u8], label: &str) -> TcpAttempt {
    let key: TcpBackoffKey = (dst.to_string(), port);
    let attempt = match TCP_BACKOFF.try_begin(&key, now_monotonic()) {
        Some(guard) => guard,
        None => {
            ldebug!(
                "[{}] TCP fallback to {}:{} skipped (backoff or connecting)",
                label, dst, port
            );
            return TcpAttempt::Skipped;
        }
    };
    let addr = format!("{}:{}", dst, port);
    let connected: Result<TcpStream, std::io::Error> = async {
        let mut remote =
            match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
                Ok(r) => r?,
                Err(_) => return Err(std::io::ErrorKind::TimedOut.into()),
            };
        let _ = remote.set_nodelay(true);
        remote.write_all(init).await?;
        Ok(remote)
    }
    .await;

    match connected {
        Ok(remote) => {
            // Как в оригинале: отметка «идёт попытка» снимается сразу после
            // установления соединения, до долгого bridge.
            drop(attempt);
            TCP_BACKOFF.record_success(&key);
            TcpAttempt::Connected(remote)
        }
        Err(e) => {
            let delay = TCP_BACKOFF.record_failure(&key, now_monotonic());
            lwarn!(
                "[{}] TCP fallback to {}:{} failed: {}; retry in {:.0}s",
                label, dst, port, e, delay
            );
            TcpAttempt::Failed {
                blocked: is_port_blocking_io_error(&e),
            }
        }
    }
}

/// TCP fallback: перебирает `ports` по порядку (port_order) и переходит к
/// следующему, если порт пропущен бэкоффом или похоже заблокирован (таймаут,
/// сброс). Рабочий порт запоминается для `dst`.
pub async fn tcp_fallback<R, W>(
    conn_read: R,
    conn_write: W,
    dst: &str,
    ports: &[u16],
    init: &[u8],
    label: String,
    ctx_streams: (TrackedStream, TrackedStream, TrackedStream, TrackedStream),
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let mut remote = None;
    for (i, &port) in ports.iter().enumerate() {
        match tcp_fallback_attempt(dst, port, init, &label).await {
            TcpAttempt::Connected(r) => {
                if i > 0 || port != PORT_TLS {
                    linfo!("[{}] TCP fallback connected to {}:{}", label, dst, port);
                }
                remember_port(PortRoute::TcpFallback, dst, port);
                remote = Some(r);
                break;
            }
            TcpAttempt::Skipped => continue,
            TcpAttempt::Failed { blocked: true } => continue,
            TcpAttempt::Failed { blocked: false } => break,
        }
    }
    let Some(remote) = remote else {
        return false;
    };
    STATS.connections_tcp_fallback.fetch_add(1, Ordering::Relaxed);

    let (clt_dec, clt_enc, tg_enc, tg_dec) = ctx_streams;
    bridge_tcp(
        conn_read,
        conn_write,
        remote,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
    true
}

// ---------------------------------------------------------------------------
// Cfproxy fallback — мобильная версия (параллель + 429 cooldown + DoH),
// путь и secure как в оригинале.
// ---------------------------------------------------------------------------

async fn try_cfproxy_base_domain(
    dc: i32,
    base_domain: &str,
    ws_path: &str,
) -> (Option<RawWebSocket>, String) {
    let base_domain = normalize_cf_domain(base_domain);
    if base_domain.is_empty() {
        return (None, String::new());
    }
    let remaining = cfproxy_429_cooldown_remaining(&base_domain);
    if remaining > Duration::ZERO {
        ldebug!(
            " CF skip {}: 429 cooldown {:.0}s",
            base_domain,
            remaining.as_secs_f64().ceil()
        );
        return (None, String::new());
    }
    let _permit = match acquire_cfproxy_attempt_slot().await {
        Some(p) => p,
        None => return (None, String::new()),
    };

    let domain = format!("kws{}.{}", dc, base_domain);
    ldebug!(" CF try {}", domain);

    let (ws, resolved_ip, err) = cf_connect_domain(&domain, ws_path, 5.0).await;
    if let Some(e) = err {
        // Cooldown ставим ТОЛЬКО при HTTP 429, иначе любой reset/timeout
        // выжигал бы домены и плодил лавину cooldown.
        if is_http_status_error(&e, 429) {
            mark_cfproxy_429_cooldown(&base_domain, &e);
        }
        if !resolved_ip.is_empty() {
            log_cf_conn_error(
                &format!(" CF fail {} via {}: {}", domain, resolved_ip, e.compact()),
                &e,
            );
        } else {
            log_cf_conn_error(&format!(" CF fail {}: {}", domain, e.compact()), &e);
        }
        return (None, String::new());
    }

    clear_cfproxy_429_cooldown(&base_domain);
    if !resolved_ip.is_empty() {
        ldebug!(" CF ok {} via {}", domain, resolved_ip);
    } else {
        ldebug!(" CF ok {} via hostname", domain);
    }
    (ws, base_domain)
}

// Только устанавливает WS-соединение через CF, НЕ трогая conn.
async fn cfproxy_acquire_ws(
    dc: i32,
    is_media: bool,
    ws_path: &str,
    cancel_token: &CancellationToken,
) -> Option<(RawWebSocket, String)> {
    let (enabled, domains) = {
        let cfg = CFPROXY.read();
        (
            CFPROXY_ENABLED.load(Ordering::Relaxed),
            cfg.domains.clone(),
        )
    };
    if !enabled || domains.is_empty() {
        return None;
    }

    let ordered = crate::balancer::BALANCER.read().get_domains_for_dc(dc);
    if ordered.is_empty() {
        return None;
    }

    let m_tag = if is_media { " media" } else { "" };
    ldebug!(" CF fallback DC{}{}: {} домен(ов)", dc, m_tag, ordered.len());

    let mut ws: Option<RawWebSocket> = None;
    let mut chosen_domain = String::new();

    if !ordered.is_empty() && !ordered[0].is_empty() {
        let (w, d) = try_cfproxy_base_domain(dc, &ordered[0], ws_path).await;
        ws = w;
        chosen_domain = d;
    }

    if ws.is_none() && ordered.len() > 1 {
        let remaining_domains: Vec<String> = ordered[1..].to_vec();
        let sem = Arc::new(tokio::sync::Semaphore::new(CFPROXY_FALLBACK_PARALLEL));
        let mut handles = Vec::new();
        for bd in remaining_domains {
            let sem = sem.clone();
            let cancel = cancel_token.clone();
            let ws_path = ws_path.to_string();
            handles.push(tokio::spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => None,
                    r = async {
                        let _p = sem.acquire().await.ok()?;
                        let (w, d) = try_cfproxy_base_domain(dc, &bd, &ws_path).await;
                        w.map(|ws| (ws, d))
                    } => r,
                }
            }));
        }
        for h in handles {
            if let Ok(Some((w, d))) = h.await {
                if ws.is_none() {
                    ws = Some(w);
                    chosen_domain = d;
                } else {
                    tokio::spawn(async move {
                        w.close().await;
                    });
                }
            }
        }
    }

    match ws {
        Some(w) => {
            if !chosen_domain.is_empty() {
                if crate::balancer::BALANCER.write().update_domain_for_dc(dc, &chosen_domain) {
                    linfo!(" CF домен для DC{} -> {}", dc, chosen_domain);
                }
            }
            Some((w, chosen_domain))
        }
        None => {
            lwarn!(" CF fallback DC{}{}: все CF домены недоступны", dc, m_tag);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// doFallback — порт bridge.do_fallback: cf_worker -> cf -> tcp.
// CF не "съедает" conn при провале: тот же conn уходит в TCP fallback.
// halves передаются дальше только в успешную ветвь: worker-ws и cf-ws
// добываются БЕЗ halves, затем halves уходят в bridge/tcp.
// ---------------------------------------------------------------------------

pub async fn do_fallback<R, W>(
    pools: &ProxyPools,
    conn_read: R,
    conn_write: W,
    relay_init: &[u8],
    label: String,
    dc: i32,
    is_test: bool,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    clt_dec: &TrackedStream,
    clt_enc: &TrackedStream,
    tg_enc: &TrackedStream,
    tg_dec: &TrackedStream,
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let m_tag = if is_media { " media" } else { "" };
    let fallback_dst = resolve_fallback_target(dc, is_media, is_test);
    let use_cf = CFPROXY_ENABLED.load(Ordering::Relaxed) && !is_test;
    let worker_domains = CF_WORKER_DOMAINS.read().clone();
    let ws_path = ws_path_for(is_test);
    let use_worker = !worker_domains.is_empty() && !fallback_dst.is_empty() && !is_test;

    // Шаг 1: worker-ws (без halves) — порт _cfproxy_worker_fallback.
    if use_worker {
        let pooled = pools
            .cf_worker
            .get(dc, fallback_dst.clone(), worker_domains.clone());
        let worker_ws = if let Some((ws, worker_domain)) = pooled {
            linfo!(
                "[{}] DC{}{} -> CF worker pool hit via {} for {}",
                label, dc, m_tag, worker_domain, fallback_dst
            );
            Some(ws)
        } else {
            let secure = cf_use_tls();
            let query = format!("dst={}&dc={}", fallback_dst, dc);
            let path = format!("/apiws?{}", query);
            let mut found = None;
            for worker_domain in pools.cf_worker.available_domains(worker_domains.clone()).await {
                linfo!(
                    "[{}] DC{}{} -> trying CF worker {} for {}",
                    label, dc, m_tag, worker_domain, fallback_dst
                );
                match ws_connect_full_opts(
                    &worker_domain,
                    &worker_domain,
                    &path,
                    10.0,
                    None,
                    secure,
                )
                .await
                {
                    Ok(ws) => {
                        found = Some(ws);
                        break;
                    }
                    Err(exc) => {
                        pools.cf_worker.report_failure(&worker_domain, &exc).await;
                        lwarn!(
                            "[{}] DC{}{} CF worker {} failed: {}",
                            label, dc, m_tag, worker_domain, exc.compact()
                        );
                    }
                }
            }
            found
        };
        if let Some(ws) = worker_ws {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            if ws.send(relay_init).await.is_ok() {
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    None, // оригинал: splitter=None для worker
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                cancel_token,
                )
                .await;
                return true;
            }
            ws.close().await;
            // send failed — падаем сквозь к CF/TCP на тех же halves.
        }
    }

    // Шаг 2: cf-ws (без halves).
    if use_cf {
        if let Some((ws, _chosen_domain)) =
            cfproxy_acquire_ws(dc, is_media, ws_path, &cancel_token).await
        {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            linfo!(" DC{}{} подключен через CF", dc, m_tag);

            if ws.send(relay_init).await.is_ok() {
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    splitter,
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                    cancel_token,
                )
                .await;
                return true;
            }
            ws.close().await;
            // CF умер сразу после хендшейка — пробуем TCP на том же conn.
        }
        // CF не дал ws — halves НЕ тронуты, идём в TCP fallback ниже.
    }

    // Шаг 3: tcp. Сначала 443, в режиме «порт 80» — затем 80.
    if !fallback_dst.is_empty() {
        let ports = port_order(PortRoute::TcpFallback, &fallback_dst);
        linfo!(
            "[{}] DC{}{} -> TCP fallback to {} (ports {:?})",
            label, dc, m_tag, fallback_dst, ports
        );
        return tcp_fallback(
            conn_read,
            conn_write,
            &fallback_dst,
            &ports,
            relay_init,
            label,
            (
                clt_dec.clone_state(),
                clt_enc.clone_state(),
                tg_enc.clone_state(),
                tg_dec.clone_state(),
            ),
            cancel_token,
        )
        .await;
    }

    false
}

// ---------------------------------------------------------------------------
// Client serving — порт tg_ws_proxy._handle_client (dd + ee/FakeTLS).
// ---------------------------------------------------------------------------

async fn read_proxy_protocol_line(conn: &mut TcpStream) -> Option<String> {
    let mut line = Vec::with_capacity(108);
    let mut byte = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = conn.read(&mut byte).await.map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
            if line.len() > 108 {
                break;
            }
        }
        Ok::<(), ()>(())
    })
    .await;
    match res {
        Ok(Ok(())) => Some(String::from_utf8_lossy(&line).to_string()),
        _ => None,
    }
}

pub async fn handle_client(
    pools: Arc<ProxyPools>,
    mut conn: TcpStream,
    cancel_token: CancellationToken,
) {
    STATS.connections_total.fetch_add(1, Ordering::Relaxed);
    STATS.connections_active.fetch_add(1, Ordering::Relaxed);
    struct ActiveGuard;
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            if STATS.connections_active.load(Ordering::Relaxed) > 0 {
                STATS.connections_active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    let _guard = ActiveGuard;

    let peer = conn
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut label = peer;

    let _ = conn.set_nodelay(true);

    let current_secret = PROXY_SECRET.read().clone();
    let secret_bytes = hex::decode(&current_secret).unwrap_or_default();

    // PROXY protocol (proxy_config.proxy_protocol в оригинале).
    if PROXY_PROTOCOL.load(Ordering::Relaxed) {
        match read_proxy_protocol_line(&mut conn).await {
            Some(line) => {
                let text = line.trim().to_string();
                if text.starts_with("PROXY ") {
                    let parts: Vec<&str> = text.split_whitespace().collect();
                    if parts.len() >= 6 {
                        label = format!("{}:{}", parts[2], parts[4]);
                    }
                    ldebug!("[{}] PROXY protocol: {}", label, text);
                } else {
                    ldebug!("[{}] expected PROXY header, got: {:?}", label, &text[..text.len().min(60)]);
                }
            }
            None => {
                ldebug!("[{}] disconnected during PROXY header", label);
                return;
            }
        }
    }

    // FakeTLS (ee-secret): первый байт решает всё — как _read_client_init.
    let masking = FAKE_TLS_DOMAIN.read().clone();
    if !masking.is_empty() {
        let mut first = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut first)).await
        {
            Ok(Ok(_)) => {}
            _ => {
                ldebug!("[{}] client disconnected before handshake", label);
                return;
            }
        }
        if first[0] == faketls::TLS_RECORD_HANDSHAKE {
            match faketls::server_handshake(conn, first[0], &secret_bytes, &masking, &label).await
            {
                Some(plain) => {
                    serve_core(
                        &pools,
                        plain.read,
                        plain.write,
                        label,
                        secret_bytes,
                        cancel_token,
                    )
                    .await;
                }
                None => {}
            }
            return;
        } else {
            ldebug!("[{}] non-TLS byte 0x{:02X} -> HTTP redirect", label, first[0]);
            let redirect = format!(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                masking
            );
            let _ = conn.write_all(redirect.as_bytes()).await;
            return;
        }
    }

    let (conn_read, conn_write) = tokio::io::split(conn);
    serve_core(
        &pools,
        conn_read,
        conn_write,
        label,
        secret_bytes,
        cancel_token,
    )
    .await;
}

/// Ядро обслуживания соединения: 64-байтный handshake → маршрут → bridge.
/// Generic над транспортом (TcpStream-halves или FakeTLS-duplex-halves).
/// _drain_bad_handshake из 1636903. Читает и выбрасывает входящие
/// данные, пока не наберётся `limit` байт, не придёт EOF/ошибка или не
/// истечёт `timeout`. Отмена (StopProxy) прерывает ожидание сразу.
/// Возвращает число вычитанных байт.
async fn drain_bad_handshake<R>(
    reader: &mut R,
    cancel: &CancellationToken,
    limit: usize,
    timeout: Duration,
) -> usize
where
    R: AsyncReadExt + Unpin,
{
    let mut buf = [0u8; 4096];
    let mut drained = 0usize;
    let drain = async {
        while drained < limit {
            let want = buf.len().min(limit - drained);
            match reader.read(&mut buf[..want]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => drained += n,
            }
        }
    };
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = tokio::time::timeout(timeout, drain) => {}
    }
    drained
}

async fn serve_core<R, W>(
    pools: &ProxyPools,
    mut conn_read: R,
    mut conn_write: W,
    label: String,
    secret_bytes: Vec<u8>,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // 64-байтный handshake
    let mut handshake = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(10), conn_read.read_exact(&mut handshake)).await
    {
        Ok(Ok(_)) => {}
        _ => {
            ldebug!("[{}] client disconnected before handshake", label);
            return;
        }
    }

    if is_http_transport(&handshake) {
        STATS.connections_http_reject.fetch_add(1, Ordering::Relaxed);
        let _ = conn_write
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
            .await;
        let _ = conn_write.shutdown().await;
        return;
    }

    // _try_handshake: key = SHA256(prekey + secret).
    let clt_dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let clt_dec_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut hash_dec = Sha256::new();
    hash_dec.update(clt_dec_prekey);
    hash_dec.update(&secret_bytes);
    let mut clt_decryptor = new_aes_ctr(&hash_dec.finalize(), clt_dec_iv);

    let mut decrypted = handshake;
    clt_decryptor.xor(&mut decrypted);

    let proto_tag = &decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4];
    let proto = LittleEndian::read_u32(proto_tag);
    if !valid_proto(proto) {
        STATS.connections_bad.fetch_add(1, Ordering::Relaxed);
        lwarn!("[{}] bad handshake (wrong secret or proto)", label);
        drain_bad_handshake(
            &mut conn_read,
            &cancel_token,
            BAD_HANDSHAKE_DRAIN_LIMIT,
            BAD_HANDSHAKE_DRAIN_TIMEOUT,
        )
        .await;
        return;
    }

    let dc_raw = LittleEndian::read_u16(&decrypted[DC_IDX_POS..DC_IDX_POS + 2]) as i16;
    let mut dc = dc_raw as i32;
    if dc < 0 {
        dc = -dc;
    }
    let is_media = dc_raw < 0;

    // Test DC: proxy_config.force_test_dc или dc >= 10000.
    let mut is_test_dc = FORCE_TEST_DC.load(Ordering::Relaxed) || dc >= 10000;
    if dc >= 10000 {
        linfo!("[{}] test DC{} -> DC{}", label, dc, dc - 10000);
        dc -= 10000;
    }
    // force_test_dc тянет весь трафик на тестовые IP/путь.
    if FORCE_TEST_DC.load(Ordering::Relaxed) {
        is_test_dc = true;
    }
    let m_tag = if is_media { " media" } else { "" };

    let proto_int = proto; // u32 tag; MsgSplitter маппит через proto_tag_to_type
    let dc_idx = if is_media { -dc } else { dc };

    ldebug!(
        "[{}] handshake ok: DC{}{} proto=0x{:08X}{}",
        label,
        dc,
        m_tag,
        proto_int,
        if is_test_dc { " test" } else { "" }
    );

    // relayInit генерация (1-в-1 c Go + RESERVED из utils.py).
    let mut relay_init = [0u8; 64];
    loop {
        rand::thread_rng().fill_bytes(&mut relay_init);
        if relay_init[0] == RESERVED_FIRST_BYTE {
            continue;
        }
        if is_reserved_start(&relay_init[..4]) {
            continue;
        }
        if relay_init[4] == 0 && relay_init[5] == 0 && relay_init[6] == 0 && relay_init[7] == 0 {
            continue;
        }
        break;
    }

    let mut tg_dec_prekey_and_iv = [0u8; 48];
    for i in 0..48 {
        tg_dec_prekey_and_iv[i] = relay_init[8 + 47 - i];
    }

    let mut tg_encryptor = new_aes_ctr(&relay_init[8..40], &relay_init[40..56]);
    let tg_decryptor = new_aes_ctr(&tg_dec_prekey_and_iv[..32], &tg_dec_prekey_and_iv[32..]);

    let mut dc_bytes = [0u8; 2];
    LittleEndian::write_u16(&mut dc_bytes, dc_idx as u16);

    let mut tail_plain = [0u8; 8];
    tail_plain[0..4].copy_from_slice(proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_bytes);
    rand::thread_rng().fill_bytes(&mut tail_plain[6..8]);

    let mut encrypted_full = relay_init;
    tg_encryptor.xor(&mut encrypted_full);

    let mut keystream_tail = [0u8; 8];
    for i in 0..8 {
        keystream_tail[i] = encrypted_full[56 + i] ^ relay_init[56 + i];
        relay_init[56 + i] = tail_plain[i] ^ keystream_tail[i];
    }

    // clt_encryptor: prekey/iv = reverse(client_dec_prekey_iv), key=SHA256+secret.
    let mut clt_enc_prekey_and_iv = [0u8; 48];
    for i in 0..48 {
        clt_enc_prekey_and_iv[i] = handshake[8 + 47 - i];
    }
    let mut hash_enc = Sha256::new();
    hash_enc.update(&clt_enc_prekey_and_iv[..32]);
    hash_enc.update(&secret_bytes);
    let clt_encryptor = new_aes_ctr(&hash_enc.finalize(), &clt_enc_prekey_and_iv[32..]);

    let dc_key = DcKey::new(dc, is_media, is_test_dc);
    let now = now_monotonic();
    let ws_path = ws_path_for(is_test_dc);

    let target_opt = resolve_configured_target(dc, is_media);
    let dc_configured = target_opt.is_some();
    let target = target_opt.unwrap_or_default();

    let blacklisted = WS_BLACKLIST.read().get(&dc_key).copied().unwrap_or(false);
    let ip_cooldown_active = !target.is_empty() && ip_cooldown_active(&target, now);
    let is_any_cf_fallback =
        CFPROXY_ENABLED.load(Ordering::Relaxed) || !CF_WORKER_DOMAINS.read().is_empty();

    // Fallback если DC нет в конфиге, WS в чёрном списке или IP на cooldown —
    // порт ветки из _handle_client оригинала.
    let mut pooled_ws: Option<RawWebSocket> = None;
    let mut use_pooled_direct = false;
    if !dc_configured || blacklisted || (ip_cooldown_active && is_any_cf_fallback) {
        if !dc_configured {
            linfo!("[{}] DC{} not in config -> fallback", label, dc);
        } else if blacklisted {
            linfo!("[{}] DC{}{} WS blacklisted -> fallback", label, dc, m_tag);
        } else {
            // Шанс пулу при случайном таймауте: пробуем забрать готовый WS.
            if !is_test_dc {
                let domains = ws_domains(dc, is_media);
                pooled_ws = pools
                    .ws
                    .get(dc, is_media, target.clone(), domains)
                    .await;
            }
            if pooled_ws.is_none() {
                linfo!(
                    "[{}] DC{}{} WS connect to {} was timed out -> fallback",
                    label, dc, m_tag, target
                );
            } else {
                linfo!(
                    "[{}] DC{}{} WS connect to {} was timed out, but pool hit -> using WS",
                    label, dc, m_tag, target
                );
                use_pooled_direct = true;
            }
        }

        if !use_pooled_direct {
            let splitter = MsgSplitter::new(proto_int);
            let ok = do_fallback(
                pools,
                conn_read,
                conn_write,
                &relay_init,
                label.clone(),
                dc,
                is_test_dc,
                is_media,
                splitter,
                &clt_decryptor,
                &clt_encryptor,
                &tg_encryptor,
                &tg_decryptor,
                cancel_token,
            )
            .await;
            if !ok {
                lwarn!("[{}] DC{}{} no fallback available", label, dc, m_tag);
            }
            return;
        }
    }

    let fail_until = DC_FAIL_UNTIL.read().get(&dc_key).copied().unwrap_or(0.0);
    let ws_timeout = if now < fail_until {
        WS_FAIL_TIMEOUT
    } else {
        WS_DIRECT_TIMEOUT
    };

    let domains = ws_domains(dc, is_media);
    // pooled_ws уже может держать WS из cooldown-ветки.
    let mut ws_opt = pooled_ws;
    let mut ws_failed_redirect = false;
    let mut ws_timed_out = false;
    let mut all_redirects = true;

    if ws_opt.is_none() && !is_test_dc {
        ws_opt = pools
            .ws
            .get(dc, is_media, target.clone(), domains.clone())
            .await;
        if ws_opt.is_some() {
            linfo!("[{}] DC{}{} -> pool hit via {}", label, dc, m_tag, target);
        }
    }

    if ws_opt.is_none() {
        for domain in &domains {
            let url = format!("wss://{}{} via {}", domain, ws_path, target);
            linfo!("[{}] DC{}{} -> {}", label, dc, m_tag, url);
            match connect_direct_ws_ports(&label, &target, domain, ws_path, ws_timeout).await {
                Ok(ws) => {
                    all_redirects = false;
                    ws_opt = Some(ws);
                    break;
                }
                Err(WsError::Handshake(h)) if h.is_redirect() => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    ws_failed_redirect = true;
                    lwarn!(
                        "[{}] DC{}{} got {} from {} -> {}",
                        label,
                        dc,
                        m_tag,
                        h.status_code,
                        domain,
                        if h.location.is_empty() { "?" } else { &h.location }
                    );
                    continue;
                }
                Err(WsError::Handshake(h)) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    all_redirects = false;
                    lwarn!(
                        "[{}] DC{}{} WS handshake: {}",
                        label, dc, m_tag, h.status_line
                    );
                    continue;
                }
                Err(WsError::Timeout) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    ws_timed_out = true;
                    lwarn!(
                        "[{}] DC{}{} WS connect timed out via {}",
                        label, dc, m_tag, domain
                    );
                    break;
                }
                Err(exc) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    all_redirects = false;
                    lwarn!(
                        "[{}] DC{}{} WS connect failed: {}",
                        label, dc, m_tag, exc.compact()
                    );
                    continue;
                }
            }
        }
    } else {
        all_redirects = false;
    }

    // WS failed -> fallback (порт оригинала 1-в-1).
    if ws_opt.is_none() {
        if ws_timed_out && !target.is_empty() {
            let cooldown = ip_cooldown_record_failure(&target, now);
            linfo!(
                "[{}] DC{}{} WS connect to {} timed out, cooldown for {}s",
                label, dc, m_tag, target, cooldown as i64
            );
        }

        if ws_failed_redirect && all_redirects {
            WS_BLACKLIST.write().insert(dc_key, true);
            lwarn!("[{}] DC{}{} blacklisted for WS (all 302)", label, dc, m_tag);
        } else if ws_failed_redirect {
            DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);
        } else {
            DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);
            linfo!(
                "[{}] DC{}{} WS failed for {}s",
                label, dc, m_tag, DC_FAIL_COOLDOWN as i64
            );
        }

        let splitter_fb = MsgSplitter::new(proto_int);
        let ok = do_fallback(
            pools,
            conn_read,
            conn_write,
            &relay_init,
            label.clone(),
            dc,
            is_test_dc,
            is_media,
            splitter_fb,
            &clt_decryptor,
            &clt_encryptor,
            &tg_encryptor,
            &tg_decryptor,
            cancel_token,
        )
        .await;
        if ok {
            linfo!("[{}] DC{}{} fallback closed", label, dc, m_tag);
        }
        return;
    }

    ip_cooldown_record_success(&target);
    pools.ws.report_success(dc, is_media).await;
    STATS.connections_ws.fetch_add(1, Ordering::Relaxed);

    let splitter = MsgSplitter::new(proto_int);
    if splitter.is_some() {
        ldebug!(
            "[{}] MsgSplitter activated for proto 0x{:08X}",
            label, proto_int
        );
    }

    // send direct init (с retry на свежий WS как мобильное улучшение).
    let mut ws = ws_opt.take().unwrap();
    let mut send_ok = ws.send(&relay_init).await.is_ok();
    if send_ok {
        ldebug!(" direct relayInit sent DC{}{}", dc, m_tag);
    } else {
        lwarn!(" direct relayInit write fail DC{}{}: closed", dc, m_tag);
        ws.close().await;

        DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);

        lwarn!(" direct retry fresh ws DC{}{}", dc, m_tag);
        let (retry_ws, retry_failed_redirect, retry_all_redirects) =
            connect_direct_ws(&target, &domains, ws_timeout, ws_path).await;
        match retry_ws {
            None => {
                if retry_failed_redirect && retry_all_redirects {
                    WS_BLACKLIST.write().insert(dc_key, true);
                    lwarn!(" DC{}{} заблокирован (302)", dc, m_tag);
                }
                lwarn!(" direct fallback DC{}{}", dc, m_tag);
                let splitter_fb = MsgSplitter::new(proto_int);
                do_fallback(
                    pools,
                    conn_read,
                    conn_write,
                    &relay_init,
                    label,
                    dc,
                    is_test_dc,
                    is_media,
                    splitter_fb,
                    &clt_decryptor,
                    &clt_encryptor,
                    &tg_encryptor,
                    &tg_decryptor,
                    cancel_token,
                )
                .await;
                return;
            }
            Some(rws) => {
                if rws.send(&relay_init).await.is_err() {
                    lwarn!(" direct relayInit write fail DC{}{}: closed", dc, m_tag);
                    rws.close().await;
                    lwarn!(" direct fallback DC{}{}", dc, m_tag);
                    let splitter_fb = MsgSplitter::new(proto_int);
                    do_fallback(
                        pools,
                        conn_read,
                        conn_write,
                        &relay_init,
                        label,
                        dc,
                        is_test_dc,
                        is_media,
                        splitter_fb,
                        &clt_decryptor,
                        &clt_encryptor,
                        &tg_encryptor,
                        &tg_decryptor,
                        cancel_token,
                    )
                    .await;
                    return;
                }
                ws = rws;
                send_ok = true;
            }
        }
    }
    let _ = send_ok;

    DC_FAIL_UNTIL.write().remove(&dc_key);
    bridge_ws(
        conn_read,
        conn_write,
        ws,
        label,
        dc,
        is_media,
        splitter,
        clt_decryptor,
        clt_encryptor,
        tg_encryptor,
        tg_decryptor,
        cancel_token,
    )
    .await;
}

// connectDirectWS — прямой перебор доменов (тихий, для retry-пути).
pub async fn connect_direct_ws(
    target: &str,
    domains: &[String],
    timeout: f64,
    ws_path: &str,
) -> (Option<RawWebSocket>, bool, bool) {
    if domains.is_empty() {
        return (None, false, false);
    }
    let mut ws_failed_redirect = false;
    let mut all_redirects = true;

    for dom in domains {
        match connect_direct_ws_ports("retry", target, dom, ws_path, timeout).await {
            Ok(ws) => return (Some(ws), ws_failed_redirect, false),
            Err(WsError::Handshake(h)) => {
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                if h.is_redirect() {
                    ws_failed_redirect = true;
                } else {
                    all_redirects = false;
                }
            }
            Err(WsError::Timeout) => {
                // Как в оригинале: таймаут прерывает перебор, all_redirects не трогаем.
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Err(_) => {
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                all_redirects = false;
            }
        }
    }
    (None, ws_failed_redirect, all_redirects)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub async fn run_proxy(
    pools: Arc<ProxyPools>,
    host: String,
    port: u16,
    dc_opt_map: HashMap<i32, String>,
    cancel_root: CancellationToken,
    listener: TcpListener,
) -> std::io::Result<()> {
    {
        let mut m = DC_OPT.write();
        *m = dc_opt_map.clone();
    }

    start_cfproxy_refresh();

    {
        let p = pools.clone();
        let map = dc_opt_map.clone();
        tokio::spawn(async move {
            p.warmup(&map).await;
        });
    }

    linfo!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    linfo!("  TG WS Proxy запущен");
    linfo!("  Адрес: {}:{}", host, port);
    linfo!("  Target DC IPs:");
    let mut dcs: Vec<i32> = dc_opt_map.keys().copied().collect();
    dcs.sort();
    for dc in dcs {
        if let Some(ip) = dc_opt_map.get(&dc) {
            linfo!("    DC{}: {}", dc, ip);
        }
    }
    if CFPROXY_ENABLED.load(Ordering::Relaxed) {
        linfo!("  CF proxy:      enabled");
    }
    if !CF_WORKER_DOMAINS.read().is_empty() {
        linfo!(
            "  CF worker:     enabled ({})",
            CF_WORKER_DOMAINS.read().join(", ")
        );
    }
    if port80_fallback_enabled() {
        linfo!("  Port 80:       CF proxy/worker on 80; direct WS and TCP fallback 443, then 80");
    }
    if !FAKE_TLS_DOMAIN.read().is_empty() {
        linfo!("  Fake TLS:      {}", FAKE_TLS_DOMAIN.read().clone());
    }

    let cancel_stats = cancel_root.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel_stats.cancelled() => return,
                _ = interval.tick() => {
                    linfo!(" {}", STATS.summary_ru());
                }
            }
        }
    });

    loop {
        tokio::select! {
            _ = cancel_root.cancelled() => {
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((conn, _)) => {
                        let p = pools.clone();
                        let cancel = cancel_root.child_token();
                        tokio::spawn(async move {
                            handle_client(p, conn, cancel).await;
                        });
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        }
    }

    drop(listener);
    cancel_root.cancel();
    tokio::time::sleep(Duration::from_millis(100)).await;
    pools.close_all().await;
    Ok(())
}

pub fn parse_cidr_pool(cidrs_str: &str) -> HashMap<i32, String> {
    let mut result = HashMap::new();
    if cidrs_str.trim().is_empty() {
        return result;
    }
    for pair in cidrs_str.split(',') {
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() == 2 {
            let dc_raw = parts[0].trim();
            let ip_raw = parts[1].trim();
            if let Ok(dc) = dc_raw.parse::<i32>() {
                if !ip_raw.is_empty() {
                    if let Ok(ip) = ip_raw.parse::<std::net::IpAddr>() {
                        result.insert(dc, ip.to_string());
                    }
                }
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Тесты: бэкофф TCP fallback и пул CF worker.
// Сценарии пула перенесены из десктопного tests/test_pool.py::CfWorkerPoolTest.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tcp_backoff_tests {
    use super::*;

    fn key(port: u16) -> TcpBackoffKey {
        ("192.0.2.1".to_string(), port)
    }

    #[test]
    fn skips_while_connecting_and_releases_on_drop() {
        let backoff = TcpBackoff::new();
        let k = key(443);
        let guard = backoff.try_begin(&k, 0.0).expect("first attempt");
        assert!(backoff.is_connecting(&k));
        assert!(backoff.try_begin(&k, 0.0).is_none());
        // другой порт — другой ключ
        assert!(backoff.try_begin(&key(80), 0.0).is_some());
        drop(guard);
        assert!(!backoff.is_connecting(&k));
        assert!(backoff.try_begin(&k, 0.0).is_some());
    }

    #[test]
    fn failures_grow_until_cap_and_success_resets() {
        let backoff = TcpBackoff::new();
        let k = key(443);
        let now = 1000.0;
        assert_eq!(backoff.record_failure(&k, now), 30.0);
        assert!(backoff.try_begin(&k, now + 29.9).is_none());
        assert!(backoff.try_begin(&k, now + 30.0).is_some());
        assert_eq!(backoff.record_failure(&k, now), 60.0);
        assert_eq!(backoff.failures(&k), Some((2, now + 60.0)));
        for _ in 0..10 {
            backoff.record_failure(&k, now);
        }
        assert_eq!(backoff.failures(&k).unwrap().1, now + TCP_BACKOFF_MAX);
        backoff.record_success(&k);
        assert_eq!(backoff.failures(&k), None);
        assert!(backoff.try_begin(&k, now).is_some());
    }

    #[test]
    fn clear_drops_failures_and_connecting() {
        let backoff = TcpBackoff::new();
        let k = key(443);
        backoff.record_failure(&k, 0.0);
        let guard = backoff.try_begin(&key(80), 0.0).unwrap();
        backoff.clear();
        assert_eq!(backoff.failures(&k), None);
        assert!(!backoff.is_connecting(&key(80)));
        drop(guard); // повторное снятие отметки безопасно
    }

    fn streams() -> (TrackedStream, TrackedStream, TrackedStream, TrackedStream) {
        let k = [7u8; 32];
        let iv = [9u8; 16];
        (
            new_aes_ctr(&k, &iv),
            new_aes_ctr(&k, &iv),
            new_aes_ctr(&k, &iv),
            new_aes_ctr(&k, &iv),
        )
    }

    #[tokio::test]
    async fn refused_fallback_sets_backoff_and_next_call_is_skipped() {
        let _lock = crate::config::GLOBAL_STATE_TEST_LOCK.lock().await;
        // Порт, на котором заведомо никто не слушает.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let k: TcpBackoffKey = ("127.0.0.1".to_string(), port);
        for attempt in 0..2 {
            let (client, _peer) = tokio::io::duplex(64);
            let (r, w) = tokio::io::split(client);
            let started = std::time::Instant::now();
            let ok = tcp_fallback(
                r,
                w,
                "127.0.0.1",
                &[port],
                &[0u8; 64],
                format!("test#{}", attempt),
                streams(),
                CancellationToken::new(),
            )
            .await;
            assert!(!ok);
            // Вторая попытка не идёт в сеть: счётчик неудач не растёт.
            assert_eq!(TCP_BACKOFF.failures(&k).map(|(n, _)| n), Some(1));
            assert!(!TCP_BACKOFF.is_connecting(&k));
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        TCP_BACKOFF.record_success(&k);
    }
}

#[cfg(test)]
mod cf_worker_pool_tests {
    use super::*;
    use std::sync::atomic::Ordering::SeqCst;

    const DST: &str = "192.0.2.2";

    // POOL_SIZE и CF_WORKER_DOMAINS — глобальные; тесты пула идут по одному.
    use crate::config::GLOBAL_STATE_TEST_LOCK as POOL_TEST_LOCK;

    struct Globals {
        pool_size: i32,
        worker_domains: Vec<String>,
    }

    impl Globals {
        fn set(pool_size: i32) -> Self {
            let saved = Globals {
                pool_size: POOL_SIZE.load(SeqCst),
                worker_domains: CF_WORKER_DOMAINS.read().clone(),
            };
            POOL_SIZE.store(pool_size, SeqCst);
            *CF_WORKER_DOMAINS.write() = vec!["worker.example".to_string()];
            saved
        }
    }

    impl Drop for Globals {
        fn drop(&mut self) {
            POOL_SIZE.store(self.pool_size, SeqCst);
            *CF_WORKER_DOMAINS.write() = std::mem::take(&mut self.worker_domains);
        }
    }

    fn timings() -> CfWorkerPoolTimings {
        CfWorkerPoolTimings {
            max_age: 60.0,
            check_interval: 0.01,
            backoff_initial: 60.0,
            backoff_max: 3600.0,
            idle_stop: 300.0,
        }
    }

    fn domains() -> Vec<String> {
        vec!["worker.example".to_string()]
    }

    /// Только DC2 идёт через CF worker (как dc_redirects без DC2 в десктопном тесте).
    fn dc_opt_without_2() -> HashMap<i32, String> {
        DC_DEFAULT_IPS
            .iter()
            .filter(|(dc, _)| **dc != 2)
            .map(|(dc, ip)| (*dc, ip.to_string()))
            .collect()
    }

    type Script = Arc<parking_lot::Mutex<VecDeque<Option<(RawWebSocket, String)>>>>;

    /// Пул с подменённым connect: очередные ответы берутся из `script`;
    /// когда сценарий кончился — connect висит до отмены.
    fn pool(t: CfWorkerPoolTimings) -> (Arc<CfWorkerPool>, Script) {
        let pool = Arc::new(CfWorkerPool::with_timings(CancellationToken::new(), t));
        let script: Script = Arc::new(parking_lot::Mutex::new(VecDeque::new()));
        let s = script.clone();
        *pool.connect_hook.lock() = Some(Arc::new(move |_dc| {
            let next = s.lock().pop_front();
            Box::pin(async move {
                match next {
                    Some(answer) => answer,
                    None => std::future::pending().await,
                }
            })
        }));
        (pool, script)
    }

    async fn wait_for(what: &str, mut pred: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !pred() {
            assert!(std::time::Instant::now() < deadline, "timeout: {}", what);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    async fn assert_peer_closed(mut peer: TcpStream) {
        let mut buf = [0u8; 64];
        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match peer.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => continue, // close-фрейм
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "WS не закрыт");
    }

    fn calls(pool: &CfWorkerPool) -> usize {
        pool.connect_calls.load(SeqCst)
    }

    fn bucket_domains(pool: &CfWorkerPool, dc: i32) -> Vec<String> {
        pool.state
            .lock()
            .slots
            .get(&dc)
            .map(|s| s.bucket.iter().map(|e| e.worker_domain.clone()).collect())
            .unwrap_or_default()
    }

    fn with_slot<R>(pool: &CfWorkerPool, dc: i32, f: impl FnOnce(&mut CfWorkerSlot) -> R) -> R {
        let mut st = pool.state.lock();
        let slot = st
            .slots
            .entry(dc)
            .or_insert_with(|| CfWorkerSlot::new(now_monotonic()));
        f(slot)
    }

    fn push_idle(pool: &CfWorkerPool, dc: i32, ws: RawWebSocket, created: f64, domain: &str) {
        with_slot(pool, dc, |s| {
            s.bucket.push_back(CfWorkerEntry {
                ws,
                created,
                worker_domain: domain.to_string(),
            })
        });
    }

    async fn join_tasks(pool: &CfWorkerPool) {
        let handles: Vec<_> = std::mem::take(&mut *pool.tasks.lock());
        for h in handles {
            h.await.unwrap();
        }
    }

    // Регрессия бага форка: schedule_refill не снимал DC из `refilling`,
    // и после первого попадания пул больше не пополнялся.
    #[tokio::test]
    async fn refills_again_after_every_hit() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        let (pool, script) = pool(timings());
        let (ws1, _p1) = test_ws_pair().await;
        let (ws2, _p2) = test_ws_pair().await;
        script.lock().extend([Some((ws1, "one".to_string())), Some((ws2, "two".to_string()))]);

        assert!(pool.get(2, DST.into(), domains()).is_none());
        wait_for("first refill", || bucket_domains(&pool, 2) == ["one"]).await;
        let (_, d) = pool.get(2, DST.into(), domains()).expect("hit #1");
        assert_eq!(d, "one");
        wait_for("refill after hit", || bucket_domains(&pool, 2) == ["two"]).await;
        let (_, d) = pool.get(2, DST.into(), domains()).expect("hit #2");
        assert_eq!(d, "two");
        // Третий connect висит: пополнение заказано и после второго попадания.
        wait_for("refill after hit #2", || calls(&pool) == 3).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn failed_warmup_recovers_without_new_client_requests() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        let (pool, script) = pool(CfWorkerPoolTimings {
            backoff_initial: 0.03,
            ..timings()
        });
        let (ready, _peer) = test_ws_pair().await;
        script.lock().extend([None, Some((ready, "ready".to_string()))]);

        pool.warmup(&dc_opt_without_2()).await;
        wait_for("failed refill", || {
            with_slot(&pool, 2, |s| s.failures == 1 && s.refill_after > 0.0 && !s.refilling)
        })
        .await;
        wait_for("recovered", || bucket_domains(&pool, 2) == ["ready"]).await;
        assert_eq!(calls(&pool), 2);
        with_slot(&pool, 2, |s| {
            assert_eq!(s.failures, 0);
            assert_eq!(s.refill_after, 0.0);
        });
        pool.close().await;
    }

    #[tokio::test]
    async fn stale_connections_are_replaced() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        // Состояния десктопного теста: expired, closed/closing, eof,
        // exception (RST), плюс CLOSE-кадр от сервера.
        for state in ["expired", "closed", "eof", "exception", "close_frame"] {
            let (pool, script) = pool(timings());
            let (stale, mut stale_peer) = test_ws_pair().await;
            let (ready, _peer) = test_ws_pair().await;
            let mut created = now_monotonic();
            let mut peer_alive = true;
            match state {
                "expired" => created -= pool.timings.max_age,
                "closed" => stale.closed.store(true, SeqCst),
                "eof" => {
                    stale_peer.shutdown().await.unwrap();
                }
                "exception" => {
                    stale_peer.set_zero_linger().unwrap();
                    drop(stale_peer);
                    peer_alive = false;
                    stale_peer = test_ws_pair().await.1;
                }
                "close_frame" => {
                    stale_peer
                        .write_all(&build_frame(OP_CLOSE, &[0x03, 0xE8], false))
                        .await
                        .unwrap();
                }
                _ => unreachable!(),
            }
            if matches!(state, "eof" | "exception" | "close_frame") {
                wait_for(state, || stale.is_stale()).await;
                // Сбрасываем флаг, чтобы проверить именно опрос сокета в get().
                stale.closed.store(false, SeqCst);
            }
            push_idle(&pool, 2, stale, created, "stale");
            script.lock().push_back(Some((ready, "ready".to_string())));

            assert!(pool.get(2, DST.into(), domains()).is_none(), "{}", state);
            wait_for(state, || bucket_domains(&pool, 2) == ["ready"]).await;
            if peer_alive {
                assert_peer_closed(stale_peer).await;
            }
            pool.close().await;
        }
    }

    #[tokio::test]
    async fn rotation_replaces_idle_connection_without_client_requests() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        let (pool, script) = pool(CfWorkerPoolTimings {
            max_age: 0.05,
            ..timings()
        });
        let (stale, stale_peer) = test_ws_pair().await;
        let (ready, _peer) = test_ws_pair().await;
        push_idle(&pool, 2, stale, now_monotonic(), "stale");
        script.lock().push_back(Some((ready, "ready".to_string())));

        pool.warmup(&dc_opt_without_2()).await;
        assert_peer_closed(stale_peer).await;
        wait_for("replaced", || bucket_domains(&pool, 2) == ["ready"]).await;
        assert_eq!(calls(&pool), 1);
        pool.close().await;
    }

    #[tokio::test]
    async fn concurrent_misses_start_only_one_background_connection() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        let (pool, _script) = pool(timings()); // connect висит
        for _ in 0..10 {
            assert!(pool.get(2, DST.into(), domains()).is_none());
        }
        wait_for("dial", || calls(&pool) == 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(calls(&pool), 1);
        pool.close().await;
    }

    #[tokio::test]
    async fn failed_refills_use_capped_exponential_backoff() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        let (pool, script) = pool(CfWorkerPoolTimings {
            backoff_initial: 1.0,
            backoff_max: 2.0,
            ..timings()
        });
        let (ready, _peer) = test_ws_pair().await;
        script
            .lock()
            .extend([None, None, None, Some((ready, "ready".to_string()))]);
        // Ротацию «выключаем», как mock _schedule_rotation в десктопном тесте.
        with_slot(&pool, 2, |s| s.rotating = true);

        for (failures, delay) in [(1u32, 1.0), (2, 2.0), (3, 2.0)] {
            with_slot(&pool, 2, |s| s.refill_after = 0.0);
            let started = now_monotonic();
            pool.schedule_refill(2, DST.into(), domains());
            join_tasks(&pool).await;
            with_slot(&pool, 2, |s| {
                assert!(!s.refilling, "guard должен снять флаг");
                assert_eq!(s.failures, failures);
                assert!(s.refill_after >= started + delay);
                assert!(s.refill_after <= now_monotonic() + delay);
            });
        }
        with_slot(&pool, 2, |s| s.refill_after = 0.0);
        pool.schedule_refill(2, DST.into(), domains());
        join_tasks(&pool).await;
        assert_eq!(bucket_domains(&pool, 2), ["ready"]);
        with_slot(&pool, 2, |s| {
            assert_eq!(s.failures, 0);
            assert_eq!(s.refill_after, 0.0);
        });
        pool.close().await;
    }

    #[tokio::test]
    async fn misses_during_backoff_do_not_retry_and_close_cancels_retry() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        let (pool, script) = pool(timings()); // backoff_initial = 60 с
        script.lock().push_back(None);

        pool.warmup(&dc_opt_without_2()).await;
        wait_for("backoff", || with_slot(&pool, 2, |s| s.failures == 1 && !s.refilling)).await;
        for _ in 0..10 {
            assert!(pool.get(2, DST.into(), domains()).is_none());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(calls(&pool), 1);
        assert!(with_slot(&pool, 2, |s| s.rotating));

        pool.close().await;
        assert!(pool.state.lock().slots.is_empty());
        assert!(pool.tasks.lock().is_empty());
        // После close() пул не запускает новых задач.
        assert!(pool.get(2, DST.into(), domains()).is_none());
        assert!(pool.tasks.lock().is_empty());
    }

    #[tokio::test]
    async fn hit_does_not_reset_failed_refill_backoff() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        let (pool, _script) = pool(timings());
        let (ready, _peer) = test_ws_pair().await;
        push_idle(&pool, 2, ready, now_monotonic(), "ready");
        let retry_at = now_monotonic() + 60.0;
        with_slot(&pool, 2, |s| {
            s.failures = 3;
            s.refill_after = retry_at;
            s.rotating = true;
        });

        let (_, d) = pool.get(2, DST.into(), domains()).expect("hit");
        assert_eq!(d, "ready");
        with_slot(&pool, 2, |s| {
            assert_eq!(s.failures, 3);
            assert_eq!(s.refill_after, retry_at);
            assert!(!s.refilling);
        });
        assert_eq!(calls(&pool), 0);
        pool.close().await;
    }

    #[tokio::test]
    async fn zero_size_and_missing_worker_domains_do_not_start_refills() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(0);
        let (pool, _script) = pool(timings());
        pool.warmup(&dc_opt_without_2()).await;
        assert!(pool.get(2, DST.into(), domains()).is_none());
        assert!(pool.tasks.lock().is_empty());

        POOL_SIZE.store(4, SeqCst);
        assert!(pool.get(2, DST.into(), Vec::new()).is_none());
        CF_WORKER_DOMAINS.write().clear();
        pool.warmup(&dc_opt_without_2()).await;
        assert!(pool.tasks.lock().is_empty());
        assert_eq!(calls(&pool), 0);
        pool.close().await;
    }

    #[tokio::test]
    async fn close_cancels_refill_and_closes_unclaimed_connections() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(1);
        let (pool, _script) = pool(timings()); // connect висит до отмены
        let (idle, idle_peer) = test_ws_pair().await;
        push_idle(&pool, 2, idle, now_monotonic(), "a.example");

        pool.schedule_refill(4, "192.0.2.4".into(), vec!["b.example".to_string()]);
        wait_for("dial", || calls(&pool) == 1).await;
        pool.close().await;

        assert!(pool.state.lock().slots.is_empty());
        assert!(pool.tasks.lock().is_empty());
        assert_peer_closed(idle_peer).await;
    }

    // Android: ротация не живёт без клиентов.
    #[tokio::test]
    async fn rotation_pauses_and_closes_pool_when_not_requested() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        let (pool, script) = pool(CfWorkerPoolTimings {
            idle_stop: 0.1,
            ..timings()
        });
        let (first, first_peer) = test_ws_pair().await;
        script.lock().push_back(Some((first, "first".to_string())));

        assert!(pool.get(2, DST.into(), domains()).is_none());
        wait_for("refilled", || bucket_domains(&pool, 2) == ["first"]).await;
        assert!(with_slot(&pool, 2, |s| s.rotating));

        // Клиентов нет: через idle_stop ротация останавливается и закрывает пул.
        wait_for("paused", || with_slot(&pool, 2, |s| !s.rotating)).await;
        assert!(bucket_domains(&pool, 2).is_empty());
        assert_peer_closed(first_peer).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(calls(&pool), 1, "без клиентов новых соединений нет");

        // Следующий запрос возобновляет ротацию и пополнение.
        let (second, _peer) = test_ws_pair().await;
        script.lock().push_back(Some((second, "second".to_string())));
        assert!(pool.get(2, DST.into(), domains()).is_none());
        wait_for("resumed", || bucket_domains(&pool, 2) == ["second"]).await;
        assert!(with_slot(&pool, 2, |s| s.rotating));
        pool.close().await;
    }

    #[test]
    fn rotation_tick_wakes_at_earliest_deadline() {
        let _g = POOL_TEST_LOCK.blocking_lock();
        let saved = POOL_SIZE.swap(4, SeqCst);
        let t = CfWorkerPoolTimings {
            max_age: 100.0,
            check_interval: 5.0,
            backoff_initial: 1.0,
            backoff_max: 3600.0,
            idle_stop: 300.0,
        };
        let pool = CfWorkerPool::with_timings(CancellationToken::new(), t);
        let now = 1000.0;
        with_slot(&pool, 2, |s| {
            s.last_requested = now - 298.0; // пауза через 2 с
            s.refill_after = now + 3.0;
        });
        let tick = pool.rotation_tick(2, 0, now).unwrap();
        assert!(!tick.idle_stop);
        assert!(tick.need_refill);
        assert_eq!(tick.wake_at, now + 2.0);

        with_slot(&pool, 2, |s| s.last_requested = now);
        assert_eq!(pool.rotation_tick(2, 0, now).unwrap().wake_at, now + 3.0);
        with_slot(&pool, 2, |s| s.refill_after = 0.0);
        assert_eq!(pool.rotation_tick(2, 0, now).unwrap().wake_at, now + 5.0);

        with_slot(&pool, 2, |s| s.last_requested = now - 300.0);
        assert!(pool.rotation_tick(2, 0, now).unwrap().idle_stop);
        // чужое поколение — тик не выполняется
        assert!(pool.rotation_tick(2, 1, now).is_none());
        POOL_SIZE.store(saved, SeqCst);
    }

    #[tokio::test]
    async fn refill_finished_after_reset_is_discarded() {
        let _lock = POOL_TEST_LOCK.lock().await;
        let _g = Globals::set(4);
        let pool = Arc::new(CfWorkerPool::with_timings(CancellationToken::new(), timings()));
        let release = Arc::new(tokio::sync::Notify::new());
        let (late, late_peer) = test_ws_pair().await;
        let late = Arc::new(parking_lot::Mutex::new(Some(late)));
        {
            let release = release.clone();
            let late = late.clone();
            *pool.connect_hook.lock() = Some(Arc::new(move |_dc| {
                let release = release.clone();
                let ws = late.lock().take();
                Box::pin(async move {
                    release.notified().await;
                    ws.map(|ws| (ws, "late".to_string()))
                })
            }));
        }
        pool.schedule_refill(2, DST.into(), domains());
        wait_for("dial", || calls(&pool) == 1).await;
        pool.reset().await;
        release.notify_one();
        assert_peer_closed(late_peer).await;
        assert!(pool.state.lock().slots.is_empty());
        pool.close().await;
    }
}

// ---------------------------------------------------------------------------
// Тесты: stale-детект в WsPool, поколение пула, OnNetworkChanged
// ---------------------------------------------------------------------------

#[cfg(test)]
mod network_change_tests {
    use super::*;
    use crate::config::GLOBAL_STATE_TEST_LOCK;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;

    const DST: &str = "192.0.2.2";
    const DEBOUNCE: Duration = Duration::from_millis(80);

    /// Сохраняет и восстанавливает глобальные настройки, которые трогает тест.
    struct Globals {
        pool_size: i32,
        worker_domains: Vec<String>,
        dc_opt: HashMap<i32, String>,
    }

    impl Globals {
        fn set(pool_size: i32) -> Self {
            let saved = Globals {
                pool_size: POOL_SIZE.load(SeqCst),
                worker_domains: std::mem::take(&mut *CF_WORKER_DOMAINS.write()),
                dc_opt: DC_OPT.read().clone(),
            };
            POOL_SIZE.store(pool_size, SeqCst);
            *DC_OPT.write() = HashMap::from([(2, DST.to_string())]);
            saved
        }
    }

    impl Drop for Globals {
        fn drop(&mut self) {
            POOL_SIZE.store(self.pool_size, SeqCst);
            *CF_WORKER_DOMAINS.write() = std::mem::take(&mut self.worker_domains);
            *DC_OPT.write() = std::mem::take(&mut self.dc_opt);
        }
    }

    fn slot() -> DcSlot {
        DcSlot { dc: 2, is_media: 0 }
    }

    async fn wait_for(what: &str, mut pred: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !pred() {
            assert!(std::time::Instant::now() < deadline, "timeout: {}", what);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    async fn assert_peer_closed(mut peer: TcpStream) {
        let mut buf = [0u8; 64];
        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match peer.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => continue,
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "WS не закрыт");
    }

    async fn push_idle(pool: &WsPool, ws: RawWebSocket) {
        let state = pool.get_slot(slot()).await;
        state.queue.lock().await.push_back(PoolEntry {
            ws,
            created: now_monotonic(),
        });
    }

    /// Хук соединений WsPool: считает вызовы и никогда не завершается.
    fn counting_hook(pool: &WsPool) -> Arc<AtomicUsize> {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        *pool.connect_hook.lock() = Some(Arc::new(move || {
            c.fetch_add(1, SeqCst);
            Box::pin(std::future::pending())
        }));
        calls
    }

    #[tokio::test]
    async fn ws_pool_get_skips_socket_closed_by_server() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let _g = Globals::set(0); // без refill
        let pool = Arc::new(WsPool::new(CancellationToken::new()));
        let (stale, stale_peer) = test_ws_pair().await;
        let (fresh, mut fresh_peer) = test_ws_pair().await;
        drop(stale_peer);
        tokio::time::sleep(Duration::from_millis(20)).await;
        push_idle(&pool, stale).await;
        push_idle(&pool, fresh).await;

        let ws = pool.get(2, false, DST.into(), vec![]).await.expect("fresh WS");
        assert_eq!(pool.idle_count().await, 0);
        // Выдан именно живой сокет: его пир получает наш кадр.
        ws.send(b"ping").await.unwrap();
        let mut buf = [0u8; 2];
        fresh_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0] & 0x0F, crate::ws::OP_BINARY);
    }

    #[tokio::test]
    async fn ws_pool_rotation_drops_socket_closed_by_server() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let _g = Globals::set(2);
        let pool = Arc::new(WsPool::new(CancellationToken::new()));
        let calls = counting_hook(&pool);
        let (stale, stale_peer) = test_ws_pair().await;
        let (fresh, _fresh_peer) = test_ws_pair().await;
        push_idle(&pool, stale).await;
        push_idle(&pool, fresh).await;
        pool.schedule_rotation(slot(), DST.into(), vec![]).await;
        drop(stale_peer);
        // Без запросов клиентов: ротация (раз в WS_POOL_CHECK_INTERVAL)
        // сама выкидывает сокет, закрытый сервером, и заказывает замену.
        let deadline = std::time::Instant::now()
            + Duration::from_secs_f64(WS_POOL_CHECK_INTERVAL + 2.0);
        while pool.idle_count().await != 1 {
            assert!(std::time::Instant::now() < deadline, "rotation did not drop stale WS");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        wait_for("refill after stale drop", || calls.load(SeqCst) >= 1).await;
        pool.cancel_token.cancel();
    }

    #[tokio::test]
    async fn ws_pool_refill_finished_after_reset_is_discarded() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let _g = Globals::set(1);
        let pool = Arc::new(WsPool::new(CancellationToken::new()));
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let (late, late_peer) = test_ws_pair().await;
        let late = Arc::new(parking_lot::Mutex::new(Some(late)));
        {
            let release = release.clone();
            let calls = calls.clone();
            *pool.connect_hook.lock() = Some(Arc::new(move || {
                calls.fetch_add(1, SeqCst);
                let release = release.clone();
                let ws = late.lock().take();
                Box::pin(async move {
                    release.notified().await;
                    ws
                })
            }));
        }
        pool.schedule_refill(slot(), DST.into(), vec![]).await;
        wait_for("dial", || calls.load(SeqCst) == 1).await;
        pool.reset().await;
        release.notify_one();
        assert_peer_closed(late_peer).await;
        assert_eq!(pool.idle_count().await, 0);
        assert!(pool.refill_failures.lock().await.is_empty());
        pool.cancel_token.cancel();
    }

    struct Seeded {
        ip: String,
        dc_fail: DcKey,
        blacklisted: DcKey,
        tcp: TcpBackoffKey,
        cf_domain: String,
    }

    fn seed_network_state() -> Seeded {
        let s = Seeded {
            ip: "198.51.100.10".to_string(),
            dc_fail: DcKey::new(4, false, false),
            blacklisted: DcKey::new(5, true, false),
            tcp: ("198.51.100.11".to_string(), 443),
            cf_domain: "cf.example".to_string(),
        };
        ip_cooldown_record_failure(&s.ip, now_monotonic());
        DC_FAIL_UNTIL.write().insert(s.dc_fail, now_monotonic() + 60.0);
        WS_BLACKLIST.write().insert(s.blacklisted, true);
        TCP_BACKOFF.record_failure(&s.tcp, now_monotonic());
        CFPROXY_429
            .write()
            .insert(s.cf_domain.clone(), Cfproxy429State { until: None, strikes: 2 });
        set_ws_pool_fronting_first(false);
        s
    }

    fn assert_network_state_reset(s: &Seeded) {
        assert!(!IP_FAIL_UNTIL.read().contains_key(&s.ip));
        assert!(!DC_FAIL_UNTIL.read().contains_key(&s.dc_fail));
        assert_eq!(TCP_BACKOFF.failures(&s.tcp), None);
        assert!(!CFPROXY_429.read().contains_key(&s.cf_domain));
        assert!(ws_pool_fronting_first());
        // «Все ответы 302» — свойство DC, а не сети: чёрный список остаётся.
        assert!(WS_BLACKLIST.read().contains_key(&s.blacklisted));
    }

    fn cleanup(s: &Seeded) {
        IP_FAIL_UNTIL.write().remove(&s.ip);
        DC_FAIL_UNTIL.write().remove(&s.dc_fail);
        WS_BLACKLIST.write().remove(&s.blacklisted);
        TCP_BACKOFF.record_success(&s.tcp);
        CFPROXY_429.write().remove(&s.cf_domain);
        set_ws_pool_fronting_first(true);
    }

    #[tokio::test]
    async fn network_change_resets_network_state_and_warms_up() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let _g = Globals::set(1);
        let cancel = CancellationToken::new();
        let pools = Arc::new(ProxyPools::with_network_debounce(cancel.clone(), DEBOUNCE));
        let calls = counting_hook(&pools.ws);
        let (idle, idle_peer) = test_ws_pair().await;
        push_idle(&pools.ws, idle).await;
        let seeded = seed_network_state();

        pools.on_network_changed(1, 2);
        // До конца дебаунса ничего не сброшено.
        assert!(IP_FAIL_UNTIL.read().contains_key(&seeded.ip));
        wait_for("reset", || !IP_FAIL_UNTIL.read().contains_key(&seeded.ip)).await;

        assert_network_state_reset(&seeded);
        assert_peer_closed(idle_peer).await;
        // Прогрев после state=1: refill для DC2 (обычный и медиа).
        wait_for("warmup", || calls.load(SeqCst) == 2).await;
        cancel.cancel();
        cleanup(&seeded);
    }

    #[tokio::test]
    async fn network_events_within_debounce_are_merged_last_one_wins() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let _g = Globals::set(1);
        let cancel = CancellationToken::new();
        let pools = Arc::new(ProxyPools::with_network_debounce(cancel.clone(), DEBOUNCE));
        let calls = counting_hook(&pools.ws);

        // «Сеть сменилась», сразу «сеть пропала»: применяется только потеря,
        // без прогрева. Если бы события не сливались, был бы прогрев.
        let seeded = seed_network_state();
        pools.on_network_changed(1, 1);
        pools.on_network_changed(0, 0);
        wait_for("reset #1", || !IP_FAIL_UNTIL.read().contains_key(&seeded.ip)).await;
        assert_network_state_reset(&seeded);
        tokio::time::sleep(DEBOUNCE * 2).await;
        assert_eq!(calls.load(SeqCst), 0, "state=0 не прогревает пул");

        // Потеря и сразу новая сеть: сброс + прогрев.
        let seeded = seed_network_state();
        pools.on_network_changed(0, 0);
        pools.on_network_changed(1, 2);
        wait_for("reset #2", || !IP_FAIL_UNTIL.read().contains_key(&seeded.ip)).await;
        wait_for("warmup", || calls.load(SeqCst) == 2).await;
        cancel.cancel();
        cleanup(&seeded);
    }

    #[tokio::test]
    async fn pending_network_change_is_dropped_on_stop() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let _g = Globals::set(1);
        let cancel = CancellationToken::new();
        let pools = Arc::new(ProxyPools::with_network_debounce(cancel.clone(), DEBOUNCE));
        let calls = counting_hook(&pools.ws);
        let seeded = seed_network_state();

        pools.on_network_changed(1, 1);
        cancel.cancel(); // StopProxy до конца дебаунса
        tokio::time::sleep(DEBOUNCE * 3).await;
        assert!(IP_FAIL_UNTIL.read().contains_key(&seeded.ip));
        assert!(pools.network_pending.lock().is_none());

        pools.on_network_changed(1, 1); // после остановки игнорируется
        tokio::time::sleep(DEBOUNCE * 3).await;
        assert!(IP_FAIL_UNTIL.read().contains_key(&seeded.ip));
        assert_eq!(calls.load(SeqCst), 0);
        cleanup(&seeded);
    }
}

// ---------------------------------------------------------------------------
// bridge_ws + MsgSplitter — перенос WsReencryptTest из tests/test_bridge.py
// (десктоп 3c54c54).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bridge_split_tests {
    use super::*;

    fn init() -> [u8; 64] {
        let mut b = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut b);
        b
    }

    fn encryptor(init: &[u8; 64]) -> TrackedStream {
        let mut enc = new_aes_ctr(&init[8..40], &init[40..56]);
        let mut skip = [0u8; 64];
        enc.xor(&mut skip);
        enc
    }

    fn abridged(payload: &[u8]) -> Vec<u8> {
        let words = payload.len() / 4;
        let mut v = if words < 0x7F {
            vec![words as u8]
        } else {
            vec![0x7F, words as u8, (words >> 8) as u8, (words >> 16) as u8]
        };
        v.extend_from_slice(payload);
        v
    }

    fn intermediate(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    /// Читает с серверного конца WS бинарные кадры клиента (с маской), пока
    /// не придёт `total` байт полезной нагрузки, CLOSE или EOF.
    async fn read_client_frames(mut peer: TcpStream, total: usize) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        loop {
            if out.iter().map(Vec::len).sum::<usize>() >= total {
                return out;
            }
            let mut hdr = [0u8; 2];
            if peer.read_exact(&mut hdr).await.is_err() {
                return out;
            }
            let opcode = hdr[0] & 0x0F;
            let mut len = (hdr[1] & 0x7F) as u64;
            if len == 126 {
                let mut b = [0u8; 2];
                peer.read_exact(&mut b).await.unwrap();
                len = u16::from_be_bytes(b) as u64;
            } else if len == 127 {
                let mut b = [0u8; 8];
                peer.read_exact(&mut b).await.unwrap();
                len = u64::from_be_bytes(b);
            }
            let mut mask = [0u8; 4];
            if hdr[1] & 0x80 != 0 {
                peer.read_exact(&mut mask).await.unwrap();
            }
            let mut payload = vec![0u8; len as usize];
            peer.read_exact(&mut payload).await.unwrap();
            xor_mask_in_place(&mut payload, &mask);
            match opcode {
                crate::ws::OP_CLOSE => return out,
                crate::ws::OP_BINARY => out.push(payload),
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn relay_preserves_encrypted_packets_and_incomplete_tail() {
        type Frame = fn(&[u8]) -> Vec<u8>;
        let cases: [(u32, Frame); 3] = [
            (0xEFEFEFEF, abridged),
            (0xEEEEEEEE, intermediate),
            (0xDDDDDDDD, intermediate),
        ];
        for (proto, frame) in cases {
            let packets = vec![
                frame(&[b'a'; 8]),
                frame(&[b'b'; 16]),
                frame(&vec![b'c'; 70000]),
                frame(&[b'd'; 32])[..7].to_vec(),
            ];
            let (client_init, relay_init) = (init(), init());
            let mut data = packets.concat();
            encryptor(&client_init).xor(&mut data);

            let (mut client, proxy_side) = tokio::io::duplex(1 << 20);
            let (r, w) = tokio::io::split(proxy_side);
            let (ws, peer) = test_ws_pair().await;
            let frames = tokio::spawn(read_client_frames(peer, data.len()));
            let cancel = CancellationToken::new();

            client.write_all(&data).await.unwrap();
            client.shutdown().await.unwrap();

            let bridge = tokio::spawn(bridge_ws(
                    r,
                    w,
                    ws,
                    "framing-test".to_string(),
                    2,
                    false,
                    MsgSplitter::new(proto),
                    encryptor(&client_init),
                    encryptor(&init()),
                    encryptor(&relay_init),
                    encryptor(&init()),
                    cancel.clone(),
            ));

            let sent = tokio::time::timeout(Duration::from_secs(5), frames)
                .await
                .expect("all frames received")
                .unwrap();
            // После EOF клиента сессия завершается сама, не дожидаясь
            // BRIDGE_READ_TIMEOUT (фикс потерянного notify_waiters).
            tokio::time::timeout(Duration::from_secs(5), bridge)
                .await
                .expect("bridge_ws finished after client EOF")
                .unwrap();
            assert!(!cancel.is_cancelled(), "родительский токен не трогается");
            let mut decoder = encryptor(&relay_init);
            let decoded: Vec<Vec<u8>> = sent
                .into_iter()
                .map(|mut part| {
                    decoder.xor(&mut part);
                    part
                })
                .collect();
            assert_eq!(decoded, packets, "proto={:08X}", proto);
            drop(client);
        }
    }
}

// ---------------------------------------------------------------------------
// Ограниченное чтение после плохого handshake
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bad_handshake_drain_tests {
    use super::*;

    #[tokio::test]
    async fn stops_at_limit() {
        let (mut client, mut proxy_side) = tokio::io::duplex(1 << 20);
        client.write_all(&vec![0u8; 200 * 1024]).await.unwrap();
        let n = drain_bad_handshake(
            &mut proxy_side,
            &CancellationToken::new(),
            BAD_HANDSHAKE_DRAIN_LIMIT,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(n, BAD_HANDSHAKE_DRAIN_LIMIT);
    }

    #[tokio::test]
    async fn stops_at_eof() {
        let (mut client, mut proxy_side) = tokio::io::duplex(1 << 16);
        client.write_all(&[1u8; 1000]).await.unwrap();
        drop(client);
        let n = drain_bad_handshake(
            &mut proxy_side,
            &CancellationToken::new(),
            BAD_HANDSHAKE_DRAIN_LIMIT,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(n, 1000);
    }

    #[tokio::test]
    async fn stops_at_timeout_when_client_stays_silent() {
        assert_eq!(BAD_HANDSHAKE_DRAIN_TIMEOUT, Duration::from_secs(10));
        assert_eq!(BAD_HANDSHAKE_DRAIN_LIMIT, 64 * 1024);
        let (_client, mut proxy_side) = tokio::io::duplex(1 << 16);
        let started = std::time::Instant::now();
        let n = drain_bad_handshake(
            &mut proxy_side,
            &CancellationToken::new(),
            BAD_HANDSHAKE_DRAIN_LIMIT,
            Duration::from_millis(100),
        )
        .await;
        assert_eq!(n, 0);
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(100) && waited < Duration::from_secs(2), "{:?}", waited);
    }

    #[tokio::test]
    async fn cancel_interrupts_drain_immediately() {
        let (_client, mut proxy_side) = tokio::io::duplex(1 << 16);
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            c.cancel();
        });
        let started = std::time::Instant::now();
        drain_bad_handshake(&mut proxy_side, &cancel, BAD_HANDSHAKE_DRAIN_LIMIT, Duration::from_secs(10)).await;
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn bad_handshake_keeps_connection_open_and_drains() {
        // Через serve_core: 64 байта мусора вместо handshake. Прокси не
        // закрывает соединение сразу и продолжает читать.
        let pools = ProxyPools::new(CancellationToken::new());
        let (mut client, proxy_side) = tokio::io::duplex(1 << 20);
        let (r, w) = tokio::io::split(proxy_side);
        let cancel = CancellationToken::new();
        let bad_before = STATS.connections_bad.load(Ordering::SeqCst);
        let server = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                serve_core(&pools, r, w, "drain-test".into(), vec![0x11; 16], cancel).await;
            })
        };
        // Не HTTP; с этим секретом расшифровывается в неверный proto tag
        // (детерминированно: секрет и мусор фиксированы).
        let mut junk = [0u8; 64];
        junk[0] = 0xAB;
        client.write_all(&junk).await.unwrap();
        client.write_all(&[7u8; 4096]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!server.is_finished(), "соединение закрыто сразу после плохого handshake");
        assert!(STATS.connections_bad.load(Ordering::SeqCst) > bad_before);
        // Клиент закрывает — прокси выходит (EOF), не дожидаясь 10 с.
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
        drop(cancel);
    }
}

// ---------------------------------------------------------------------------
// Фикс завершения сессий: отмена между задачами моста не теряется
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bridge_shutdown_tests {
    use super::*;

    fn streams() -> (TrackedStream, TrackedStream, TrackedStream, TrackedStream) {
        let k = [3u8; 32];
        let iv = [5u8; 16];
        (
            new_aes_ctr(&k, &iv),
            new_aes_ctr(&k, &iv),
            new_aes_ctr(&k, &iv),
            new_aes_ctr(&k, &iv),
        )
    }

    #[tokio::test]
    async fn ws_session_ends_right_after_client_eof() {
        // Клиент закрывается сразу, upstream молчит. Раньше down-задача
        // могла не получить сигнал и ждать 120 с.
        for _ in 0..20 {
            let (client, proxy_side) = tokio::io::duplex(1 << 16);
            drop(client);
            let (r, w) = tokio::io::split(proxy_side);
            let (ws, _peer) = test_ws_pair().await;
            let (a, b, c, d) = streams();
            tokio::time::timeout(
                Duration::from_secs(2),
                bridge_ws(r, w, ws, "eof".into(), 2, false, None, a, b, c, d, CancellationToken::new()),
            )
            .await
            .expect("bridge_ws hung after client EOF");
        }
    }

    #[tokio::test]
    async fn tcp_session_ends_right_after_client_eof() {
        for _ in 0..20 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (remote, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
            let _silent_tg = accepted.unwrap().0;
            let (client, proxy_side) = tokio::io::duplex(1 << 16);
            drop(client);
            let (r, w) = tokio::io::split(proxy_side);
            let (a, b, c, d) = streams();
            tokio::time::timeout(
                Duration::from_secs(2),
                bridge_tcp(r, w, remote.unwrap(), a, b, c, d, CancellationToken::new()),
            )
            .await
            .expect("bridge_tcp hung after client EOF");
        }
    }

    #[tokio::test]
    async fn stop_cancels_running_ws_session() {
        let (_client, proxy_side) = tokio::io::duplex(1 << 16);
        let (r, w) = tokio::io::split(proxy_side);
        let (ws, _peer) = test_ws_pair().await;
        let (a, b, c, d) = streams();
        let stop = CancellationToken::new();
        let session = tokio::spawn(bridge_ws(r, w, ws, "stop".into(), 2, false, None, a, b, c, d, stop.clone()));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!session.is_finished());
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(2), session).await.unwrap().unwrap();
    }
}

// ---------------------------------------------------------------------------
// Режим «порт 80» — 443, затем 80, с запоминанием рабочего порта
// ---------------------------------------------------------------------------

#[cfg(test)]
mod port80_tests {
    use super::*;
    use crate::config::GLOBAL_STATE_TEST_LOCK;

    struct Port80Mode(bool);

    impl Port80Mode {
        fn set(on: bool) -> Self {
            let saved = Port80Mode(DISABLE_SECURE.load(Ordering::SeqCst));
            DISABLE_SECURE.store(on, Ordering::SeqCst);
            reset_port_memory();
            saved
        }
    }

    impl Drop for Port80Mode {
        fn drop(&mut self) {
            DISABLE_SECURE.store(self.0, Ordering::SeqCst);
            reset_port_memory();
        }
    }

    fn streams() -> (TrackedStream, TrackedStream, TrackedStream, TrackedStream) {
        let k = [1u8; 32];
        let iv = [2u8; 16];
        (new_aes_ctr(&k, &iv), new_aes_ctr(&k, &iv), new_aes_ctr(&k, &iv), new_aes_ctr(&k, &iv))
    }

    fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn port_order_follows_mode_and_memory() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let ip = "192.0.2.50";
        {
            let _m = Port80Mode::set(false);
            assert!(cf_use_tls());
            assert_eq!(port_order(PortRoute::DirectWs, ip), [443]);
            assert_eq!(port_order(PortRoute::TcpFallback, ip), [443]);
            // Память без режима «порт 80» не включает 80.
            remember_port(PortRoute::DirectWs, ip, 80);
            assert_eq!(port_order(PortRoute::DirectWs, ip), [443]);
        }
        {
            let _m = Port80Mode::set(true);
            assert!(!cf_use_tls());
            assert_eq!(port_order(PortRoute::DirectWs, ip), [443, 80]);
            remember_port(PortRoute::DirectWs, ip, 80);
            assert_eq!(port_order(PortRoute::DirectWs, ip), [80, 443]);
            // Маршруты и цели запоминаются раздельно.
            assert_eq!(port_order(PortRoute::TcpFallback, ip), [443, 80]);
            assert_eq!(port_order(PortRoute::DirectWs, "192.0.2.51"), [443, 80]);
            // 443 снова заработал — возвращается первым.
            remember_port(PortRoute::DirectWs, ip, 443);
            assert_eq!(port_order(PortRoute::DirectWs, ip), [443, 80]);
            remember_port(PortRoute::DirectWs, ip, 80);
            reset_port_memory();
            assert_eq!(port_order(PortRoute::DirectWs, ip), [443, 80]);
        }
    }

    #[tokio::test]
    async fn network_change_forgets_working_ports() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let _m = Port80Mode::set(true);
        let saved_pool = POOL_SIZE.swap(0, Ordering::SeqCst);
        remember_port(PortRoute::TcpFallback, "192.0.2.52", 80);
        let cancel = CancellationToken::new();
        let pools = Arc::new(ProxyPools::with_network_debounce(cancel.clone(), Duration::from_millis(10)));
        pools.on_network_changed(1, 1);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while port_order(PortRoute::TcpFallback, "192.0.2.52") != [443, 80] {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        cancel.cancel();
        POOL_SIZE.store(saved_pool, Ordering::SeqCst);
    }

    #[test]
    fn only_timeouts_and_resets_switch_port() {
        use std::io::{Error, ErrorKind};
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
        ] {
            assert!(is_port_blocking_ws_error(&WsError::Io(Error::from(kind))), "{:?}", kind);
        }
        assert!(is_port_blocking_ws_error(&WsError::Timeout));
        // Ответ сервера и прочее — порт рабочий, второй не пробуем.
        let redirect = WsError::Handshake(crate::ws::WsHandshakeError {
            status_code: 302,
            status_line: "HTTP/1.1 302 Found".into(),
            headers: HashMap::new(),
            location: String::new(),
        });
        assert!(!is_port_blocking_ws_error(&redirect));
        assert!(!is_port_blocking_ws_error(&WsError::Io(Error::from(ErrorKind::PermissionDenied))));
        assert!(!is_port_blocking_ws_error(&WsError::Other("x".into())));
    }

    #[tokio::test]
    async fn tcp_fallback_moves_to_next_port_and_remembers_it() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let _m = Port80Mode::set(true);
        let dead = closed_port();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alive = listener.local_addr().unwrap().port();
        let got_init = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut init = [0u8; 64];
            s.read_exact(&mut init).await.unwrap();
            init
        });

        let (client, _peer) = tokio::io::duplex(64);
        let (r, w) = tokio::io::split(client);
        let cancel = CancellationToken::new();
        let session = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                tcp_fallback(r, w, "127.0.0.1", &[dead, alive], &[0x5A; 64], "ports".into(), streams(), cancel)
                    .await
            }
        });
        let init = tokio::time::timeout(Duration::from_secs(5), got_init).await.unwrap().unwrap();
        assert_eq!(init, [0x5A; 64]);
        assert_eq!(
            WORKING_PORT.lock().get(&(PortRoute::TcpFallback, "127.0.0.1".to_string())),
            Some(&alive)
        );
        // Неудачный порт получил бэкофф, рабочий — нет.
        assert_eq!(TCP_BACKOFF.failures(&("127.0.0.1".to_string(), dead)).map(|f| f.0), Some(1));
        assert_eq!(TCP_BACKOFF.failures(&("127.0.0.1".to_string(), alive)), None);
        cancel.cancel();
        assert!(tokio::time::timeout(Duration::from_secs(2), session).await.unwrap().unwrap());
        TCP_BACKOFF.record_success(&("127.0.0.1".to_string(), dead));
    }

    #[tokio::test]
    async fn tcp_fallback_skips_port_in_backoff() {
        let _lock = GLOBAL_STATE_TEST_LOCK.lock().await;
        let dead = closed_port();
        let key = ("127.0.0.1".to_string(), dead);
        TCP_BACKOFF.record_failure(&key, now_monotonic());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alive = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move { listener.accept().await.is_ok() });
        let (client, _peer) = tokio::io::duplex(64);
        let (r, w) = tokio::io::split(client);
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        let session = tokio::spawn(async move {
            tcp_fallback(r, w, "127.0.0.1", &[dead, alive], &[0u8; 64], "skip".into(), streams(), c).await
        });
        assert!(tokio::time::timeout(Duration::from_secs(5), accepted).await.unwrap().unwrap());
        // Пропуск по бэкоффу не считается новой неудачей.
        assert_eq!(TCP_BACKOFF.failures(&key).map(|f| f.0), Some(1));
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), session).await;
        TCP_BACKOFF.record_success(&key);
        reset_port_memory();
    }
}
