//! Порт proxy/cf_websocket.py десктопа (v1.12.0: 219f38c, 4a338a0, c01fad5,
//! f42468b): подключение к CF proxy по WebSocket с переключением
//! TLS (wss, 443) ↔ plain (ws, 80) после таймаута.
//!
//! Если TLS-рукопожатие с Cloudflare «зависает» (типичная картина DPI),
//! следующая попытка идёт без TLS, и наоборот. Пара (домен, режим), на
//! которой случился таймаут, не пробуется `CF_TIMEOUT_COOLDOWN`; успехи
//! каждого режима считаются, и новое соединение начинает с режима, у
//! которого их не меньше (`cf_prefers_tls`).
//!
//! Отличия от десктопа:
//!   * на десктопе `connect_cf_domains` обходит домены по очереди и режим
//!     меняется после каждого таймаута сквозь домены; здесь домены
//!     пробуются параллельно (cfproxy fallback в proxy.rs), поэтому
//!     чередование режимов делается внутри одного домена;
//!   * `secure == false` (режим «порт 80» в приложении) — только plain,
//!     как десктопный `--no-secure`: ни чередования, ни cooldown.

use crate::ws::WsError;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Сколько пара (домен, режим) не пробуется после таймаута.
pub const CF_TIMEOUT_COOLDOWN: Duration = Duration::from_secs(30);

/// Таймауты попыток внутри одного вызова: первая и вторая — 3 с, затем
/// длиннее (десктоп CF_CONNECT_TIMEOUTS). Номер попытки = число таймаутов
/// до неё; у нас режимов два, поэтому используются первые два значения.
pub const CF_CONNECT_TIMEOUTS: [Duration; 5] = [
    Duration::from_secs(3),
    Duration::from_secs(3),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(10),
];

/// Состояние пары (домен, режим).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cooldown {
    /// Не пробовать до этого момента.
    Until(Instant),
    /// Cooldown истёк, и одна попытка уже идёт: остальные пропускают пару
    /// (десктоп временно ставит math.inf).
    Probing,
}

#[derive(Default)]
struct CfTimeouts {
    // Ключ — базовый домен без kws{dc}: таймаут одного DC выключает
    // режим для всех DC этого домена (c01fad5).
    until: HashMap<(String, bool), Cooldown>,
}

static TIMEOUTS: Lazy<Mutex<CfTimeouts>> = Lazy::new(|| Mutex::new(CfTimeouts::default()));
static TLS_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static PLAIN_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Сброс при старте/остановке прокси и смене сети: выученный режим
/// относится к конкретной сети.
pub fn reset_cf_timeouts() {
    TIMEOUTS.lock().until.clear();
    TLS_CONNECTIONS.store(0, Ordering::Relaxed);
    PLAIN_CONNECTIONS.store(0, Ordering::Relaxed);
}

/// Какой режим пробовать первым: TLS, пока он удавался не реже plain.
pub fn cf_prefers_tls() -> bool {
    TLS_CONNECTIONS.load(Ordering::Relaxed) >= PLAIN_CONNECTIONS.load(Ordering::Relaxed)
}

/// Идёт ли для домена cooldown TLS-соединений (H2 работает только по TLS).
pub fn cf_tls_in_cooldown(name: &str) -> bool {
    cf_tls_in_cooldown_at(name, Instant::now())
}

fn cf_tls_in_cooldown_at(name: &str, now: Instant) -> bool {
    match TIMEOUTS.lock().until.get(&(name.to_string(), true)) {
        Some(Cooldown::Until(t)) => now < *t,
        Some(Cooldown::Probing) => true,
        None => false,
    }
}

/// Таймаут ли это: наш `Timeout` или ETIMEDOUT от ОС (десктоп ловит
/// `asyncio.TimeoutError` и встроенный `TimeoutError`).
pub fn is_timeout(err: &WsError) -> bool {
    match err {
        WsError::Timeout => true,
        WsError::Io(e) => e.kind() == std::io::ErrorKind::TimedOut,
        _ => false,
    }
}

/// Результат `connect_cf_modes`.
pub enum CfDial<T> {
    Connected(T),
    /// Попытка была, и она не удалась (последняя ошибка).
    Failed(WsError),
    /// Все режимы домена в cooldown: попыток не было.
    Skipped,
}

/// Разрешение на попытку для пары; `Some(prev)` — пара была в cooldown,
/// и разрешение выдано как «пробная» попытка после его истечения.
enum Admission {
    Skip,
    Go { probe_of: Option<Instant> },
}

fn admit(key: &(String, bool), now: Instant) -> Admission {
    let mut t = TIMEOUTS.lock();
    match t.until.get(key).copied() {
        None => Admission::Go { probe_of: None },
        Some(Cooldown::Probing) => Admission::Skip,
        Some(Cooldown::Until(until)) => {
            if now < until {
                Admission::Skip
            } else {
                t.until.insert(key.clone(), Cooldown::Probing);
                Admission::Go {
                    probe_of: Some(until),
                }
            }
        }
    }
}

/// Откат пробной отметки (десктоп `finally`): если попытка закончилась,
/// а пара всё ещё «Probing», возвращаем прежний срок.
fn restore_probe(key: &(String, bool), probe_of: Option<Instant>) {
    let Some(prev) = probe_of else { return };
    let mut t = TIMEOUTS.lock();
    if t.until.get(key) == Some(&Cooldown::Probing) {
        t.until.insert(key.clone(), Cooldown::Until(prev));
    }
}

fn mark_timeout(key: &(String, bool), had_cooldown: bool, now: Instant) -> bool {
    let mut t = TIMEOUTS.lock();
    if !had_cooldown && t.until.contains_key(key) {
        // Параллельная попытка уже поставила cooldown — не продлеваем.
        return false;
    }
    // Чистим давно истёкшие записи, чтобы карта не росла.
    t.until.retain(|_, c| match c {
        Cooldown::Until(until) => *until + CF_TIMEOUT_COOLDOWN > now,
        Cooldown::Probing => true,
    });
    t.until
        .insert(key.clone(), Cooldown::Until(now + CF_TIMEOUT_COOLDOWN));
    true
}

fn record_success(use_tls: bool) {
    if use_tls {
        TLS_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    } else {
        PLAIN_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Подключение к одному CF-домену с чередованием режимов.
///
/// `name` — базовый домен (ключ cooldown), `label` — для логов,
/// `max_timeout` — потолок на одну попытку, `dial(use_tls, timeout)` —
/// сама попытка. После таймаута следующая попытка идёт в другом режиме;
/// любая другая ошибка (ответил сервер или DNS) завершает вызов, а
/// cooldown пары снимается: сеть жива.
pub async fn connect_cf_modes<T, F, Fut>(
    name: &str,
    label: &str,
    secure: bool,
    max_timeout: Duration,
    mut dial: F,
) -> CfDial<T>
where
    F: FnMut(bool, Duration) -> Fut,
    Fut: Future<Output = Result<T, WsError>>,
{
    let tls_first = cf_prefers_tls();
    let modes: Vec<bool> = if secure {
        vec![tls_first, !tls_first]
    } else {
        vec![false]
    };

    let mut timeouts = 0usize;
    let mut last_err: Option<WsError> = None;
    for use_tls in modes {
        // Cooldown только у режимов, которые могут чередоваться.
        let key = (name.to_string(), use_tls);
        let probe_of = if secure {
            match admit(&key, Instant::now()) {
                Admission::Skip => continue,
                Admission::Go { probe_of } => probe_of,
            }
        } else {
            None
        };

        let attempt_timeout = max_timeout.min(CF_CONNECT_TIMEOUTS[timeouts.min(CF_CONNECT_TIMEOUTS.len() - 1)]);
        let result = dial(use_tls, attempt_timeout).await;
        if secure {
            restore_probe(&key, probe_of);
        }
        match result {
            Ok(ws) => {
                if secure {
                    TIMEOUTS.lock().until.remove(&key);
                }
                record_success(use_tls);
                return CfDial::Connected(ws);
            }
            Err(e) if secure && is_timeout(&e) => {
                if mark_timeout(&key, probe_of.is_some(), Instant::now()) {
                    crate::lwarn!(
                        "[{}] CF WebSocket timed out (host={} tls={}); retry in {:.0}s",
                        label,
                        name,
                        use_tls,
                        CF_TIMEOUT_COOLDOWN.as_secs_f64()
                    );
                }
                timeouts += 1;
                last_err = Some(e);
            }
            Err(e) => {
                if secure {
                    TIMEOUTS.lock().until.remove(&key);
                }
                return CfDial::Failed(e);
            }
        }
    }
    match last_err {
        Some(e) => CfDial::Failed(e),
        None => CfDial::Skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Состояние глобальное: тесты идут последовательно.
    static GUARD: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

    fn timeout_err() -> WsError {
        WsError::Timeout
    }

    fn refused() -> WsError {
        WsError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
    }

    type Calls = Arc<Mutex<Vec<(bool, Duration)>>>;

    fn script(results: Vec<Result<u32, WsError>>) -> (Calls, impl FnMut(bool, Duration) -> std::future::Ready<Result<u32, WsError>>) {
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(std::collections::VecDeque::from(results)));
        let c = calls.clone();
        let f = move |tls: bool, t: Duration| {
            c.lock().push((tls, t));
            let r = queue.lock().pop_front().expect("unexpected extra dial");
            std::future::ready(r)
        };
        (calls, f)
    }

    #[tokio::test]
    async fn tls_timeout_falls_back_to_plain_and_prefers_it_later() {
        let _g = GUARD.lock().await;
        reset_cf_timeouts();
        let (calls, dial) = script(vec![Err(timeout_err()), Ok(7)]);
        let r = connect_cf_modes("a.co.uk", "t", true, Duration::from_secs(10), dial).await;
        assert!(matches!(r, CfDial::Connected(7)));
        let c = calls.lock().clone();
        assert_eq!(c.iter().map(|x| x.0).collect::<Vec<_>>(), vec![true, false]);
        assert_eq!(c[0].1, Duration::from_secs(3));
        assert_eq!(c[1].1, Duration::from_secs(3));
        // plain удался, TLS — нет: теперь начинаем с plain.
        assert!(!cf_prefers_tls());
        // TLS этого домена в cooldown (нужно для H2), plain — нет.
        assert!(cf_tls_in_cooldown("a.co.uk"));
        assert!(!cf_tls_in_cooldown("b.co.uk"));
        reset_cf_timeouts();
    }

    #[tokio::test]
    async fn skips_mode_in_cooldown_and_uses_the_other() {
        let _g = GUARD.lock().await;
        reset_cf_timeouts();
        let (_, dial) = script(vec![Err(timeout_err()), Err(timeout_err())]);
        let r = connect_cf_modes("a.co.uk", "t", true, Duration::from_secs(10), dial).await;
        assert!(matches!(r, CfDial::Failed(WsError::Timeout)));
        // Оба режима в cooldown: попыток нет.
        let (calls, dial) = script(vec![]);
        let r = connect_cf_modes("a.co.uk", "t", true, Duration::from_secs(10), dial).await;
        assert!(matches!(r, CfDial::Skipped));
        assert!(calls.lock().is_empty());
        // Другой домен не затронут.
        let (calls, dial) = script(vec![Ok(1)]);
        let r = connect_cf_modes("b.co.uk", "t", true, Duration::from_secs(10), dial).await;
        assert!(matches!(r, CfDial::Connected(1)));
        assert_eq!(calls.lock().len(), 1);
        reset_cf_timeouts();
    }

    #[tokio::test]
    async fn cooldown_expires_and_failed_probe_keeps_old_deadline() {
        let _g = GUARD.lock().await;
        reset_cf_timeouts();
        let key = ("a.co.uk".to_string(), true);
        let past = Instant::now() - Duration::from_secs(1);
        TIMEOUTS.lock().until.insert(key.clone(), Cooldown::Until(past));
        // Пробная попытка после истечения: пока она идёт, пара занята.
        let probe = match admit(&key, Instant::now()) {
            Admission::Go { probe_of } => probe_of,
            Admission::Skip => panic!("expired cooldown must admit a probe"),
        };
        assert_eq!(probe, Some(past));
        assert!(matches!(admit(&key, Instant::now()), Admission::Skip));
        assert!(cf_tls_in_cooldown("a.co.uk"));
        // Проба закончилась ничем — возвращается прежний срок.
        restore_probe(&key, probe);
        assert_eq!(TIMEOUTS.lock().until.get(&key), Some(&Cooldown::Until(past)));
        reset_cf_timeouts();
    }

    #[tokio::test]
    async fn non_timeout_error_stops_without_switching_and_clears_cooldown() {
        let _g = GUARD.lock().await;
        reset_cf_timeouts();
        let (calls, dial) = script(vec![Err(refused())]);
        let r = connect_cf_modes("a.co.uk", "t", true, Duration::from_secs(10), dial).await;
        assert!(matches!(r, CfDial::Failed(WsError::Io(_))));
        assert_eq!(calls.lock().len(), 1);
        assert!(!cf_tls_in_cooldown("a.co.uk"));
        reset_cf_timeouts();
    }

    #[tokio::test]
    async fn port80_mode_is_plain_only_without_cooldown() {
        let _g = GUARD.lock().await;
        reset_cf_timeouts();
        let (calls, dial) = script(vec![Err(timeout_err())]);
        let r = connect_cf_modes("a.co.uk", "t", false, Duration::from_secs(10), dial).await;
        assert!(matches!(r, CfDial::Failed(WsError::Timeout)));
        assert_eq!(calls.lock().iter().map(|x| x.0).collect::<Vec<_>>(), vec![false]);
        assert!(TIMEOUTS.lock().until.is_empty());
        reset_cf_timeouts();
    }

    #[tokio::test]
    async fn max_timeout_caps_attempts() {
        let _g = GUARD.lock().await;
        reset_cf_timeouts();
        let (calls, dial) = script(vec![Err(timeout_err()), Ok(1)]);
        let _ = connect_cf_modes("a.co.uk", "t", true, Duration::from_secs(2), dial).await;
        assert!(calls.lock().iter().all(|x| x.1 == Duration::from_secs(2)));
        reset_cf_timeouts();
    }

    #[test]
    fn os_timeouts_count_as_timeouts() {
        assert!(is_timeout(&WsError::Timeout));
        assert!(is_timeout(&WsError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut))));
        assert!(!is_timeout(&refused()));
        assert!(!is_timeout(&WsError::Canceled));
    }
}
