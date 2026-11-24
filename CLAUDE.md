# TG WS Proxy Android: сборка и устройство проекта

Локальный MTProto-прокси для Telegram. Сетевая логика — нативная библиотека на Rust
(`libtgwsproxy.so`), интерфейс — Kotlin + Jetpack Compose. Kotlin вызывает библиотеку
через **JNA** (`NativeProxy.kt`, интерфейс `ProxyLibrary`), не через JNI: имена
экспортируемых функций в `src/lib.rs` (`StartProxy`, `SetTlsVerify`, `SetCfH2Media`,
`OnNetworkChanged`, `GetStats` и т. д.) должны совпадать с методами `ProxyLibrary`.

## 1. Нативная библиотека (.so)

Сборка: `build_so.bat` в корне репозитория (Windows).

Нужно:
- Android SDK с установленным NDK (берётся самая новая версия из `<sdk>\ndk`).
  SDK ищется в `ANDROID_SDK_ROOT`, `ANDROID_HOME`, `sdk.dir` из `local.properties`,
  затем в `%LOCALAPPDATA%\Android\Sdk`.
- Rust (rustup, cargo). Цели `aarch64-linux-android` и `armv7-linux-androideabi`
  скрипт добавляет сам. Без MSVC `link.exe` используется host-тулчейн windows-gnu.

Что делает скрипт:
- `aarch64-linux-android`, release, линкер NDK `aarch64-linux-android24-clang` (API 24);
- `armv7-linux-androideabi`, release, линкер NDK `armv7a-linux-androideabi21-clang` (API 21);
- копирует результат из `target\<triple>\release\libtgwsproxy.so` в:
  - `app/src/main/jniLibs/arm64-v8a/libtgwsproxy.so`
  - `app/src/main/jniLibs/armeabi-v7a/libtgwsproxy.so`

Gradle берёт .so только из `app/src/main/jniLibs`, поэтому после любых изменений в `src/`
сначала пересоберите .so, потом APK.

Тесты Rust-ядра запускаются на хосте, NDK для них не нужен:

```
cargo test
cargo clippy --all-targets
```

## 2. APK (Gradle)

Отладочная сборка под одну архитектуру:

```
gradlew.bat :app:assembleArm64Debug
```

Релиз: `build_apk.bat`. Скрипт проверяет, что обе .so на месте, вызывает
`gradlew assembleRelease` и копирует три APK в `app\release\`:

| Flavor      | ABI                      | minSdk | Файл                                 |
|-------------|--------------------------|--------|--------------------------------------|
| `universal` | arm64-v8a + armeabi-v7a  | 21     | `v<версия>-android-universal.apk`    |
| `arm64`     | arm64-v8a                | 24     | `v<версия>-android-v8a-minsdk24.apk` |
| `arm32`     | armeabi-v7a              | 21     | `v<версия>-android-v7a-minsdk21.apk` |

Версия читается из `versionName` в `app/build.gradle.kts`. Для подписи релиза нужны
`KEYSTORE_FILE` и связанные ключи в `local.properties`. compileSdk/targetSdk — 35.

## 3. Где что лежит

- `src/` — Rust-ядро: `proxy.rs` (маршрутизация, пулы, fallback), `ws.rs`, `cfproxy.rs`,
  `cf_h2.rs` (HTTP/2-мультиплексирование медиа через CF), `tls.rs` (проверка сертификатов),
  `config.rs` (глобальные настройки и статистика), `lib.rs` (FFI),
  `cf_websocket.rs` (CF proxy: чередование TLS/plain после таймаута, cooldown пар
  «домен + режим», счётчик успехов режима; порт десктопа 1.12.0),
  `client_watch.rs` (отмена исходящих подключений fallback, если клиент ушёл:
  task-local с дубликатом сокета клиента, `with_client_setup`).
- `app/src/main/java/com/amurcanov/tgwsproxy/`:
  - `SettingsStore.kt` — DataStore с настройками и значениями по умолчанию;
  - `ProxyController.kt` — собирает настройки и запускает `ProxyService`;
  - `ProxyService.kt` — foreground-сервис, `startProxy()` передаёт настройки в ядро,
    поля `last…` хранят их для перезапуска;
  - `NetworkChangeMonitor.kt` — сообщает ядру о смене сети (`OnNetworkChanged`);
  - `ui/SettingsTab.kt` — экран настроек.
- `old_src_golang/` — старая реализация, в сборку не входит.

## 4. Правила

- Поддерживаются API 21+; код для API 21–23 должен оставаться рабочим.
- Новая настройка проходит путь: ключ и значение по умолчанию в `SettingsStore` →
  `ProxyController` (extra) → `ProxyService.startProxy()` (вызов FFI + поле `last…`) →
  тумблер в `SettingsTab`. Значение по умолчанию в Rust должно быть безопасным, если
  Kotlin его не передал.
