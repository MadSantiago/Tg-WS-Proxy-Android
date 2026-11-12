use aes::cipher::{KeyIvInit, StreamCipher};
use byteorder::{BigEndian, ByteOrder, LittleEndian};

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

// ---------------------------------------------------------------------------
// TrackedStream — эмулирует Go cipher.Stream с поддержкой Clone() через
// "промотку" keystream на processed байт.
// ---------------------------------------------------------------------------

pub struct TrackedStream {
    key: Vec<u8>,
    iv: Vec<u8>,
    processed: u64,
    stream: Aes256Ctr,
}

impl TrackedStream {
    pub fn new(key: &[u8], iv: &[u8]) -> TrackedStream {
        let stream = Aes256Ctr::new(key.into(), iv.into());
        TrackedStream {
            key: key.to_vec(),
            iv: iv.to_vec(),
            processed: 0,
            stream,
        }
    }

    // XOR in place (dst == src в нашем использовании)
    pub fn xor(&mut self, data: &mut [u8]) {
        self.stream.apply_keystream(data);
        self.processed += data.len() as u64;
    }

    pub fn clone_state(&self) -> TrackedStream {
        let mut clone_stream = Aes256Ctr::new(self.key.as_slice().into(), self.iv.as_slice().into());
        let mut dummy = [0u8; 16384];
        let mut rem = self.processed;
        while rem > 0 {
            let n = if rem > 16384 { 16384 } else { rem as usize };
            clone_stream.apply_keystream(&mut dummy[..n]);
            rem -= n as u64;
        }
        TrackedStream {
            key: self.key.clone(),
            iv: self.iv.clone(),
            processed: self.processed,
            stream: clone_stream,
        }
    }
}

pub fn new_aes_ctr(key: &[u8], iv: &[u8]) -> TrackedStream {
    TrackedStream::new(key, iv)
}

// ---------------------------------------------------------------------------
// MTProto Splitter
// ---------------------------------------------------------------------------

pub const PROTO_ABRIDGED: i32 = 0;
pub const PROTO_INTERMEDIATE: i32 = 1;
pub const PROTO_PADDED_INTERMEDIATE: i32 = 2;

pub fn proto_tag_to_type(proto: u32) -> i32 {
    match proto {
        0xEEEEEEEE => PROTO_INTERMEDIATE,
        0xDDDDDDDD => PROTO_PADDED_INTERMEDIATE,
        _ => PROTO_ABRIDGED,
    }
}

/// Делит поток к Telegram на отдельные транспортные пакеты MTProto, чтобы
/// каждый ушёл отдельным WS-кадром. Порт MsgSplitter из proxy/bridge.py
/// после 3c54c54: открытый текст передаётся снаружи (он уже есть после
/// clt_dec), собственного AES-CTR на ключах relay_init больше нет — минус
/// один проход AES на каждый байт upstream.
pub struct MsgSplitter {
    proto_type: i32,
    // Хвост незавершённого пакета с прошлых чанков.
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    disabled: bool,
}

/// Результат разбора: пакеты (шифртекст) и сколько байт входа съедено.
struct Scan {
    parts: Vec<Vec<u8>>,
    consumed: usize,
    disable: bool,
}

impl MsgSplitter {
    /// Option сохранён ради вызывающего кода; сейчас всегда Some.
    pub fn new(proto: u32) -> Option<MsgSplitter> {
        Some(MsgSplitter {
            proto_type: proto_tag_to_type(proto),
            cipher_buf: Vec::new(),
            plain_buf: Vec::new(),
            disabled: false,
        })
    }

    /// `chunk` — шифртекст для Telegram, `plain` — тот же чанк в открытом
    /// виде (после clt_dec, до tg_enc). Длины совпадают.
    pub fn split(&mut self, chunk: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        if chunk.is_empty() {
            return Vec::new();
        }
        if self.disabled {
            return vec![chunk.to_vec()];
        }
        debug_assert_eq!(chunk.len(), plain.len());

        // Быстрый путь (аналог 3fa2816): хвоста нет — разбираем чанк прямо
        // на месте, без копирования в буферы. В буфер уходит только
        // незавершённый остаток.
        if self.cipher_buf.is_empty() {
            let scan = Self::scan(self.proto_type, chunk, plain);
            self.disabled = scan.disable;
            if scan.consumed < chunk.len() {
                self.cipher_buf.extend_from_slice(&chunk[scan.consumed..]);
                self.plain_buf.extend_from_slice(&plain[scan.consumed..]);
            }
            return scan.parts;
        }

        self.cipher_buf.extend_from_slice(chunk);
        self.plain_buf.extend_from_slice(plain);
        let scan = Self::scan(self.proto_type, &self.cipher_buf, &self.plain_buf);
        self.disabled = scan.disable;
        // Один drain в конце, а не по пакету: O(N) на чанке из мелких пакетов.
        if scan.consumed > 0 {
            self.cipher_buf.drain(..scan.consumed);
            self.plain_buf.drain(..scan.consumed);
        }
        scan.parts
    }

    fn scan(proto_type: i32, cipher: &[u8], plain: &[u8]) -> Scan {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut offset: usize = 0;
        let len = cipher.len();
        while offset < len {
            match next_packet_len(proto_type, &plain[offset..]) {
                None => break,
                Some(0) => {
                    // Пакет нулевой длины: протокол не распознан, дальше
                    // поток идёт как есть.
                    parts.push(cipher[offset..].to_vec());
                    return Scan {
                        parts,
                        consumed: len,
                        disable: true,
                    };
                }
                Some(n) => {
                    parts.push(cipher[offset..offset + n].to_vec());
                    offset += n;
                }
            }
        }
        Scan {
            parts,
            consumed: offset,
            disable: false,
        }
    }

    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            return Vec::new();
        }
        self.plain_buf.clear();
        vec![std::mem::take(&mut self.cipher_buf)]
    }
}

/// Длина очередного пакета в начале `plain`: None — данных пока мало,
/// Some(0) — пакет нулевой длины (разбиение отключается).
fn next_packet_len(proto_type: i32, plain: &[u8]) -> Option<usize> {
    let header = transport_header(proto_type, plain)?;
    if header.payload_len == 0 {
        return Some(0);
    }
    let pkt_len = header.header_len + header.payload_len;
    if plain.len() < pkt_len {
        return None;
    }
    Some(pkt_len)
}

/// Заголовок транспортного пакета MTProto (открытый текст после clt_dec).
/// Общий для MsgSplitter и H2 (`cf_h2::read_packet`), чтобы правила длины
/// не расходились.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportHeader {
    /// 1 или 4 байта (abridged), 4 (intermediate и padded).
    pub header_len: usize,
    /// Длина тела в байтах, без заголовка.
    pub payload_len: usize,
    /// Флаг quick ack: старший бит первого байта (abridged) или длины.
    pub quick: bool,
}

/// Сколько байт заголовка нужно, зная первый байт (abridged: 1 или 4).
pub fn transport_header_len(proto_type: i32, first: u8) -> usize {
    match proto_type {
        PROTO_ABRIDGED if first & 0x7F == 0x7F => 4,
        PROTO_ABRIDGED => 1,
        _ => 4,
    }
}

/// Разбирает заголовок в начале `plain`. None — данных на заголовок пока
/// мало. Протокол вне трёх известных даёт нулевую длину.
pub fn transport_header(proto_type: i32, plain: &[u8]) -> Option<TransportHeader> {
    let first = *plain.first()?;
    let header_len = transport_header_len(proto_type, first);
    if plain.len() < header_len {
        return None;
    }
    let header = match proto_type {
        // _next_abridged_len: длинная форма при first == 0x7F или 0xFF
        // (старший бит — quick ack).
        PROTO_ABRIDGED => {
            let words = if header_len == 4 {
                (plain[1] as usize) | ((plain[2] as usize) << 8) | ((plain[3] as usize) << 16)
            } else {
                first as usize & 0x7F
            };
            TransportHeader {
                header_len,
                payload_len: words * 4,
                quick: first & 0x80 != 0,
            }
        }
        PROTO_INTERMEDIATE | PROTO_PADDED_INTERMEDIATE => {
            let value = LittleEndian::read_u32(&plain[..4]);
            TransportHeader {
                header_len,
                payload_len: (value & 0x7FFF_FFFF) as usize,
                quick: value & 0x8000_0000 != 0,
            }
        }
        _ => TransportHeader {
            header_len,
            payload_len: 0,
            quick: false,
        },
    };
    Some(header)
}

// ---------------------------------------------------------------------------
// XOR mask (websocket frame masking) — оптимизированный вариант
// ---------------------------------------------------------------------------

pub fn xor_mask_in_place(data: &mut [u8], mask: &[u8]) {
    let n = data.len();
    if n == 0 {
        return;
    }
    let mask8: u64 = (mask[0] as u64)
        | ((mask[1] as u64) << 8)
        | ((mask[2] as u64) << 16)
        | ((mask[3] as u64) << 24)
        | ((mask[0] as u64) << 32)
        | ((mask[1] as u64) << 40)
        | ((mask[2] as u64) << 48)
        | ((mask[3] as u64) << 56);

    let mut i = 0;
    while i + 8 <= n {
        let v = LittleEndian::read_u64(&data[i..]);
        LittleEndian::write_u64(&mut data[i..], v ^ mask8);
        i += 8;
    }
    while i < n {
        data[i] ^= mask[i & 3];
        i += 1;
    }
}

#[allow(dead_code)]
pub fn write_be_u16(buf: &mut [u8], v: u16) {
    BigEndian::write_u16(buf, v);
}
#[allow(dead_code)]
pub fn write_be_u64(buf: &mut [u8], v: u64) {
    BigEndian::write_u64(buf, v);
}

// ---------------------------------------------------------------------------
// Тесты MsgSplitter — перенос MsgSplitterTest из tests/test_bridge.py
// (десктоп 3c54c54).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod msg_splitter_tests {
    use super::*;
    use rand::RngCore;

    const ABRIDGED: u32 = 0xEFEFEFEF;
    const INTERMEDIATE: u32 = 0xEEEEEEEE;
    const PADDED: u32 = 0xDDDDDDDD;

    fn relay_init() -> [u8; 64] {
        let mut b = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut b);
        b
    }

    /// Шифратор к Telegram, как tg_enc в serve_core.
    fn encryptor(init: &[u8; 64]) -> TrackedStream {
        let mut enc = new_aes_ctr(&init[8..40], &init[40..56]);
        let mut skip = [0u8; 64];
        enc.xor(&mut skip);
        enc
    }

    fn encrypt(enc: &mut TrackedStream, data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        enc.xor(&mut v);
        v
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

    /// Аналог MsgSplitterTest._split: шифрует пакеты и скармливает поток
    /// чанками заданных размеров (остаток — последним чанком).
    fn split(proto: u32, packets: &[Vec<u8>], chunk_sizes: &[usize]) -> (MsgSplitter, Vec<u8>, Vec<Vec<u8>>) {
        let init = relay_init();
        let mut splitter = MsgSplitter::new(proto).unwrap();
        let plain: Vec<u8> = packets.concat();
        let stream = encrypt(&mut encryptor(&init), &plain);

        let mut bounds = Vec::new();
        let mut offset = 0;
        for &size in chunk_sizes {
            if offset >= stream.len() {
                break;
            }
            let end = (offset + size).min(stream.len());
            bounds.push((offset, end));
            offset = end;
        }
        if offset < stream.len() {
            bounds.push((offset, stream.len()));
        }

        let mut parts = Vec::new();
        for (a, b) in bounds {
            parts.extend(splitter.split(&stream[a..b], &plain[a..b]));
        }
        (splitter, stream, parts)
    }

    #[test]
    fn abridged_stream_splits_into_packets() {
        let packets = [abridged(&[b'a'; 4]), abridged(&[b'b'; 16]), abridged(&[b'c'; 40])];
        let (_, stream, parts) = split(ABRIDGED, &packets, &[]);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts.concat(), stream);
        assert_eq!(parts.iter().map(Vec::len).collect::<Vec<_>>(), [5, 17, 41]);
    }

    #[test]
    fn intermediate_stream_splits_into_packets() {
        let packets = [intermediate(&[b'a'; 8]), intermediate(&[b'b'; 12])];
        let (_, stream, parts) = split(INTERMEDIATE, &packets, &[]);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts.concat(), stream);
    }

    #[test]
    fn padded_intermediate_uses_intermediate_framing() {
        let packets = [intermediate(&[b'z'; 20])];
        let (_, stream, parts) = split(PADDED, &packets, &[]);
        assert_eq!(parts, [stream]);
    }

    #[test]
    fn partial_packet_is_buffered_until_complete() {
        let packets = [abridged(&[b'a'; 20])];
        let ones = vec![1; packets[0].len() - 1];
        let (_, stream, parts) = split(ABRIDGED, &packets, &ones);
        assert_eq!(parts, [stream]);
    }

    #[test]
    fn split_preserves_stream_across_arbitrary_chunking() {
        let packets: Vec<Vec<u8>> = (0..8u8).map(|i| intermediate(&[i; 16])).collect();
        let (_, stream, parts) = split(INTERMEDIATE, &packets, &[7, 3, 50, 11]);
        assert_eq!(parts.concat(), stream);
        assert_eq!(parts.len(), 8);
    }

    #[test]
    fn empty_chunk_yields_nothing() {
        let mut splitter = MsgSplitter::new(INTERMEDIATE).unwrap();
        assert!(splitter.split(b"", b"").is_empty());
    }

    #[test]
    fn zero_length_packet_disables_splitting() {
        let init = relay_init();
        let mut splitter = MsgSplitter::new(INTERMEDIATE).unwrap();
        let mut plain = 0u32.to_le_bytes().to_vec();
        plain.extend_from_slice(b"tail");
        let stream = encrypt(&mut encryptor(&init), &plain);
        assert_eq!(splitter.split(&stream, &plain), std::slice::from_ref(&stream));
        assert_eq!(splitter.split(b"raw", b"raw"), [b"raw".to_vec()]);
    }

    #[test]
    fn zero_length_packet_after_buffered_tail_disables_splitting() {
        // Медленный путь: хвост в буфере, затем нулевой пакет.
        let init = relay_init();
        let mut splitter = MsgSplitter::new(INTERMEDIATE).unwrap();
        let mut plain = intermediate(&[b'x'; 8]);
        plain.extend_from_slice(&0u32.to_le_bytes());
        plain.extend_from_slice(b"junk");
        let stream = encrypt(&mut encryptor(&init), &plain);
        assert!(splitter.split(&stream[..5], &plain[..5]).is_empty());
        let parts = splitter.split(&stream[5..], &plain[5..]);
        assert_eq!(parts, [stream[..12].to_vec(), stream[12..].to_vec()]);
        assert_eq!(splitter.split(b"raw", b"raw"), [b"raw".to_vec()]);
        assert!(splitter.flush().is_empty());
    }

    #[test]
    fn flush_returns_buffered_tail_once() {
        let init = relay_init();
        let mut splitter = MsgSplitter::new(INTERMEDIATE).unwrap();
        let plain = intermediate(&[b'x'; 32])[..10].to_vec();
        let partial = encrypt(&mut encryptor(&init), &plain);
        assert!(splitter.split(&partial, &plain).is_empty());
        assert_eq!(splitter.flush(), [partial]);
        assert!(splitter.flush().is_empty());
    }

    #[test]
    fn extended_and_quick_ack_headers_can_cross_chunk_boundaries() {
        type Frame = fn(&[u8]) -> Vec<u8>;
        let cases: [(u32, Frame); 3] = [(ABRIDGED, abridged), (INTERMEDIATE, intermediate), (PADDED, intermediate)];
        for (proto, frame) in cases {
            for size in [16usize, 512, 65536] {
                let mut packet = frame(&vec![b'p'; size]);
                packet[if proto == ABRIDGED { 0 } else { 3 }] |= 0x80;
                let packets = [packet.clone(), frame(&[b't'; 8])];
                for header_split in [1usize, 2, 3] {
                    let (_, stream, parts) =
                        split(proto, &packets, &[header_split, 1, 11, size - 8]);
                    assert_eq!(
                        parts,
                        [stream[..packet.len()].to_vec(), stream[packet.len()..].to_vec()],
                        "proto={:08X} size={} header_split={}",
                        proto,
                        size,
                        header_split
                    );
                }
            }
        }
    }

    #[test]
    fn random_packets_and_random_chunking_keep_packet_boundaries() {
        // Оракул независим от splitter: ожидаемые части — поток, нарезанный
        // по длинам исходных пакетов. Проверяет и быстрый путь (чанк
        // начинается с границы пакета), и медленный (хвост в буфере).
        let mut rng = rand::thread_rng();
        for proto in [ABRIDGED, INTERMEDIATE, PADDED] {
            for _ in 0..50 {
                let packets: Vec<Vec<u8>> = (0..(1 + rng.next_u32() % 12))
                    .map(|_| {
                        let words = 1 + (rng.next_u32() % 300) as usize;
                        let mut payload = vec![0u8; words * 4];
                        rng.fill_bytes(&mut payload);
                        if proto == ABRIDGED { abridged(&payload) } else { intermediate(&payload) }
                    })
                    .collect();
                let sizes: Vec<usize> = (0..40).map(|_| 1 + (rng.next_u32() % 700) as usize).collect();
                let (mut splitter, stream, mut parts) = split(proto, &packets, &sizes);
                parts.extend(splitter.flush());
                let mut expected = Vec::new();
                let mut off = 0;
                for p in &packets {
                    expected.push(stream[off..off + p.len()].to_vec());
                    off += p.len();
                }
                assert_eq!(parts, expected, "proto={:08X} sizes={:?}", proto, sizes);
            }
        }
    }
}

