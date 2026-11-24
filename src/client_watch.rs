//! Порт `client_setup` из proxy/event_loop.py десктопа (v1.12.0, 13d764f
//! «Socket occupation fix»): пока прокси устанавливает исходящее соединение
//! (CF worker, CF proxy, TCP fallback), клиент мог уже уйти. Без отмены
//! такие попытки до таймаута держат сокеты и «будят» радио на мобильной сети.
//!
//! Клиентские байты при этом не читаются: следим за дубликатом дескриптора
//! клиентского сокета (`dup`): флаг read-closed у `ready(READABLE)`, а EOF
//! отличаем от «клиент прислал данные и закрыл запись» через `peek`. Во втором случае
//! попытку не отменяем (на десктопе `reader.at_eof()` в этом случае false).
//!
//! Дубликат регистрируется в epoll лениво, только когда первая попытка
//! действительно началась, поэтому обычные соединения (прямой WS) ничего
//! не платят, кроме одного `dup`.

use std::future::Future;
use std::sync::Arc;
use tokio::io::Interest;
use tokio::net::TcpStream;
use tokio::sync::OnceCell;

tokio::task_local! {
    static CLIENT_WATCH: Arc<ClientWatch>;
}

pub struct ClientWatch {
    std: parking_lot::Mutex<Option<std::net::TcpStream>>,
    stream: OnceCell<Option<TcpStream>>,
}

impl ClientWatch {
    /// `dup` клиентского сокета; None, если системный вызов не удался
    /// (тогда отмена просто не работает).
    pub fn new(client: &TcpStream) -> Option<Arc<ClientWatch>> {
        let dup = socket2::SockRef::from(client).try_clone().ok()?;
        let std: std::net::TcpStream = dup.into();
        std.set_nonblocking(true).ok()?;
        Some(Arc::new(ClientWatch {
            std: parking_lot::Mutex::new(Some(std)),
            stream: OnceCell::new(),
        }))
    }

    async fn stream(&self) -> Option<&TcpStream> {
        self.stream
            .get_or_init(|| async {
                let std = self.std.lock().take()?;
                TcpStream::from_std(std).ok()
            })
            .await
            .as_ref()
    }

    /// Завершается, когда клиент ушёл без непрочитанных данных (EOF или
    /// сброс). Если наблюдать не получается или клиент закрыл запись после
    /// отправки данных — не завершается никогда.
    pub async fn gone(&self) {
        let Some(stream) = self.stream().await else {
            return std::future::pending().await;
        };
        loop {
            match stream.ready(Interest::READABLE).await {
                Err(_) => return,
                Ok(ready) if ready.is_read_closed() => {
                    let mut b = [0u8; 1];
                    return match stream.peek(&mut b).await {
                        // EOF без данных или сброс соединения.
                        Ok(0) | Err(_) => (),
                        // Данные ещё не прочитаны: bridge увидит EOF сам.
                        Ok(_) => std::future::pending().await,
                    };
                }
                // Клиент прислал пакет, который мы не читаем: «читаемо»
                // остаётся взведённым, поэтому опрашиваем редко, а не в цикле.
                Ok(_) => tokio::time::sleep(DATA_POLL).await,
            }
        }
    }
}

const DATA_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// Выполняет `scope` с наблюдением за клиентом для `with_client_setup`.
pub async fn run_with_watch<F: Future>(watch: Option<Arc<ClientWatch>>, fut: F) -> F::Output {
    match watch {
        Some(w) => CLIENT_WATCH.scope(w, fut).await,
        None => fut.await,
    }
}

/// Выполняет установку исходящего соединения; `None` — клиент ушёл раньше,
/// future отменён (сокеты закрыты drop-ом). Вне `run_with_watch` (тесты,
/// фоновые задачи) просто выполняет future.
pub async fn with_client_setup<F: Future>(fut: F) -> Option<F::Output> {
    match CLIENT_WATCH.try_with(|w| w.clone()) {
        Ok(w) => {
            tokio::select! {
                biased;
                _ = w.gone() => None,
                r = fut => Some(r),
            }
        }
        Err(_) => Some(fut.await),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (c, s) = tokio::join!(TcpStream::connect(addr), l.accept());
        (c.unwrap(), s.unwrap().0)
    }

    async fn slow() -> u32 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        7
    }

    #[tokio::test]
    async fn without_watch_the_future_just_runs() {
        assert_eq!(with_client_setup(async { 1 }).await, Some(1));
    }

    #[tokio::test]
    async fn open_client_does_not_cancel_the_dial() {
        let (_client, server) = pair().await;
        let w = ClientWatch::new(&server);
        let r = run_with_watch(w, with_client_setup(slow())).await;
        assert_eq!(r, Some(7));
    }

    #[tokio::test]
    async fn client_eof_cancels_the_dial_without_reading_bytes() {
        let (client, mut server) = pair().await;
        let w = ClientWatch::new(&server);
        let started = std::time::Instant::now();
        let closer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(client);
        });
        let r = run_with_watch(w, with_client_setup(slow())).await;
        closer.await.unwrap();
        assert_eq!(r, None);
        assert!(started.elapsed() < Duration::from_millis(250));
        // Дубликат ничего не прочитал: в основном сокете EOF ещё виден.
        let mut buf = [0u8; 1];
        let n = tokio::io::AsyncReadExt::read(&mut server, &mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn pending_client_data_before_close_keeps_the_dial() {
        let (mut client, server) = pair().await;
        let w = ClientWatch::new(&server);
        client.write_all(b"queued packet").await.unwrap();
        client.shutdown().await.unwrap();
        let r = run_with_watch(w, with_client_setup(slow())).await;
        assert_eq!(r, Some(7));
    }

    #[tokio::test]
    async fn watch_is_reusable_for_consecutive_dials() {
        let (client, server) = pair().await;
        let w = ClientWatch::new(&server);
        let r = run_with_watch(w, async {
            let first = with_client_setup(async { 1 }).await;
            drop(client);
            let second = with_client_setup(slow()).await;
            (first, second)
        })
        .await;
        assert_eq!(r, (Some(1), None));
    }
}
