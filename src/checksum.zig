//! インターネットチェックサム (RFC 1071)
//!
//! 「データを 16bit ワードの列とみなして 1 の補数和を取り、その 1 の補数を返す」
//!
//! 検証側は「チェックサムフィールドを含めたまま全体を計算すると 0 になる」
//! という性質を使う。送信側はフィールドを 0 にして計算した結果を書き込む
//!
//! UDP / TCP は、これに加えて **疑似ヘッダ** を計算対象の先頭に足す
//!
//! IP ヘッダのチェックサムが守れるのは **1 ホップ** でしかない。TTL がホップごとに
//! 減るので、ルータは検証したあと必ず計算し直す — 宛先 IP が途中で化けても、
//! 化けた値のまま正しいチェックサムが作り直され、誤配送に誰も気づけない
//!
//! 疑似ヘッダは、その L3 のアドレスを L4 のチェックサムに焼き込む。L4 のチェックサムは
//! 送信元が 1 回計算し、宛先が 1 回検証するだけで途中の誰も触らない。つまり
//! **端点同士**でアドレスの整合性を保証できる — これが誤配送の検知
//!
//! L4 のチェックサムが L3 のフィールドを含むのは、層の厳密な分離を実用のために崩した箇所
//! IPv6 でも同じ形が残っている（RFC 768 / RFC 9293）
//!
//! IPv4 / ICMP / UDP / TCP がすべて同じアルゴリズムを使う

const std = @import("std");
const hexdump = @import("hexdump.zig");

/// バイト列全体のインターネットチェックサムを計算する。
///
/// - 2 バイトずつビッグエンディアンの 16bit ワードとして加算する
/// - 奇数長の場合、最後の 1 バイトは右側を 0 で埋めた 16bit ワードとして扱う
/// - 加算で 16bit からあふれた桁（キャリー）は下位に折り返して足す（1 の補数和）
/// - 最後に全ビットを反転して返す
pub fn compute(bytes: []const u8) u16 {
    return fold(accumulate(0, bytes));
}

/// 受信データの検証
/// チェックサムフィールドを含めたまま全体を計算して `0` になれば正しい
pub fn verify(bytes: []const u8) bool {
    return compute(bytes) == 0;
}

/// バイト列を 16bit ワードとして `acc` に足し込む。キャリーは畳まず u32 に貯める
fn accumulate(acc: u32, bytes: []const u8) u32 {
    var sum = acc;

    // 2 バイトずつワードとして足し込む
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum += hexdump.readU16(bytes[i .. i + 2]);
    }

    // 奇数長: 最後の 1 バイトを上位バイトとして扱う（右側 0 パディング）
    if (bytes.len % 2 == 1) {
        sum += @as(u32, bytes[i]) << 8;
    }

    return sum;
}

/// 部分和を 16bit に畳んで 1 の補数を取る。
fn fold(acc: u32) u16 {
    var sum = acc;

    // キャリーの折り返し:  1 回の折り返しで再びあふれることがあるのでループする
    // sum >> 16    : 上位16bitを取り出す
    // sum & 0xffff : 下位16bitを取り出す
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // 1 の補数（全ビット反転）
    return ~@as(u16, @truncate(sum));
}

/// 疑似ヘッダの長さ
pub const pseudo_header_len = 12;

/// 疑似ヘッダを組み立てる。線には出ない、宛先をチェックサムに焼き込むためだけの 12 バイト
///
///    0               8              16              24              31
///   ┌───────────────────────────────────────────────────────────────┐
///   │                     source address (IPv4)                     │
///   ├───────────────────────────────────────────────────────────────┤
///   │                  destination address (IPv4)                   │
///   ├───────────────┬───────────────┬───────────────────────────────┤
///   │       0       │   protocol    │           L4 length           │
///   └───────────────┴───────────────┴───────────────────────────────┘
pub fn pseudoHeader(src: [4]u8, dst: [4]u8, protocol: u8, length: u16) [pseudo_header_len]u8 {
    var buf: [pseudo_header_len]u8 = undefined;
    @memcpy(buf[0..4], &src);
    @memcpy(buf[4..8], &dst);
    buf[8] = 0; // 未使用。ワード境界を揃えるための詰め物
    buf[9] = protocol;
    hexdump.writeU16(buf[10..12], length);
    return buf;
}

/// 疑似ヘッダを前置してチェックサムを計算する（UDP / TCP 用）。
pub fn computeWithPseudo(pseudo: [pseudo_header_len]u8, bytes: []const u8) u16 {
    return fold(accumulate(accumulate(0, &pseudo), bytes));
}

/// 疑似ヘッダ込みの検証。
pub fn verifyWithPseudo(pseudo: [pseudo_header_len]u8, bytes: []const u8) bool {
    return computeWithPseudo(pseudo, bytes) == 0;
}

test "RFC 1071 の例" {
    // RFC 1071 Section 3 の計算例。
    // ワード列 0001 f203 f4f5 f6f7 の 1 の補数和は ddf2、
    // チェックサム（その反転）は 220d になる。
    const data = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    try std.testing.expectEqual(@as(u16, 0x220d), compute(&data));
}

test "実際の IPv4 ヘッダ: チェックサムフィールドを 0 にして計算すると元の値になる" {
    // よく知られた IPv4 ヘッダの例 (20 バイト)。
    // 本来のチェックサムは 0xb861 (11 バイト目からの 2 バイト)。
    var header = [_]u8{
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, // ← チェックサムフィールドを 0 埋め
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    };
    try std.testing.expectEqual(@as(u16, 0xb861), compute(&header));

    // 計算したチェックサムを書き込むと、全体の検証が通る
    hexdump.writeU16(header[10..], 0xb861);
    try std.testing.expect(verify(&header));
}

test "1 バイト壊れると検証が落ちる" {
    var header = [_]u8{
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    };
    try std.testing.expect(verify(&header));

    header[3] = 0x74; // TTL でも IP でもどこでもよい。1 バイト変える
    try std.testing.expect(!verify(&header));
}

test "奇数長: 最後のバイトは右側 0 パディング" {
    // 1 バイトの入力 {0x01} はワード 0x0100 として扱われる。
    // sum = 0x0100、チェックサムは ~0x0100 = 0xfeff
    try std.testing.expectEqual(@as(u16, 0xfeff), compute(&.{0x01}));
}

test "空入力: sum = 0、チェックサムは 0xffff" {
    try std.testing.expectEqual(@as(u16, 0xffff), compute(&.{}));
}

test "疑似ヘッダの組み立て" {
    // 192.168.70.1 -> 192.168.70.2、プロトコル 17 (UDP)、L4 長 13
    const pseudo = pseudoHeader(.{ 192, 168, 70, 1 }, .{ 192, 168, 70, 2 }, 17, 13);
    try std.testing.expectEqualSlices(u8, &.{
        0xc0, 0xa8, 0x46, 0x01, // 送信元 IP
        0xc0, 0xa8, 0x46, 0x02, // 宛先 IP
        0x00, // 未使用
        0x11, // プロトコル 17
        0x00, 0x0d, // L4 長 13
    }, &pseudo);
}

test "疑似ヘッダ込みの検証: 実キャプチャの UDP データグラム" {
    // tcpdump -i tap0 -xx した `echo -n hello | nc -u 192.168.70.2 7` の UDP 部分。
    // 13 バイトの奇数長なので、末尾 0 パディングの経路も通る
    const datagram = [_]u8{
        0xa6, 0x89, // 送信元ポート 42633
        0x00, 0x07, // 宛先ポート 7
        0x00, 0x0d, // 長さ 13
        0x08, 0x1d, // チェックサム
        'h',  'e',
        'l',  'l',
        'o',
    };
    const pseudo = pseudoHeader(.{ 192, 168, 70, 1 }, .{ 192, 168, 70, 2 }, 17, 13);
    try std.testing.expect(verifyWithPseudo(pseudo, &datagram));

    // 疑似ヘッダ抜きでは通らない。L4 だけを見ても検証できないのが UDP / TCP
    try std.testing.expect(!verify(&datagram));
}

test "宛先 IP が違えば検証が落ちる" {
    // 疑似ヘッダの存在理由そのもの。データグラムのバイト列は 1 ビットも
    // 変わっていないのに、届いた先が違うだけで検出できる
    const datagram = [_]u8{
        0xa6, 0x89, 0x00, 0x07, 0x00, 0x0d, 0x08, 0x1d,
        'h',  'e',  'l',  'l',  'o',
    };
    const wrong = pseudoHeader(.{ 192, 168, 70, 1 }, .{ 192, 168, 70, 9 }, 17, 13);
    try std.testing.expect(!verifyWithPseudo(wrong, &datagram));
}

test "部分和は分けて足しても同じ" {
    // accumulate が結合的であること。疑似ヘッダを別領域のまま足せる根拠
    const bytes = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    try std.testing.expectEqual(
        compute(&bytes),
        fold(accumulate(accumulate(0, bytes[0..4]), bytes[4..])),
    );
}
