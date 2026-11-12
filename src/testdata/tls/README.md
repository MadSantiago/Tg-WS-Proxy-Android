Тестовые сертификаты для `src/tls.rs` (только для unit-тестов, в .so не попадают).

- `ca.der` — самоподписанный тестовый УЦ «tgwsproxy test root», P-256.
- `leaf.der` — сертификат на `test.example`, подписан `ca.der`.
  notBefore 2026-11-12, notAfter 2126-10-19.
- `leaf.key.der` — ключ `leaf.der` (PKCS#8). Публичен намеренно, нигде,
  кроме тестов, не используется.

Сгенерированы `openssl` (ecparam prime256v1, x509 -days 36500).
