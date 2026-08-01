//! インターネットチェックサム (RFC 1071)。
//!
//! IPv4 / ICMP / UDP / TCP がすべて同じアルゴリズムを使う:
//! 「データを 16bit ワードの列とみなして 1 の補数和を取り、その 1 の補数を返す」。
//!
//! 検証側は「チェックサムフィールドを含めたまま全体を計算すると 0 になる」
//! という性質を使う。送信側はフィールドを 0 にして計算した結果を書き込む。

const std = @import("std");
const hexdump = @import("hexdump.zig");

/// バイト列全体のインターネットチェックサムを計算する。
///
/// - 2 バイトずつビッグエンディアンの 16bit ワードとして加算する
/// - 奇数長の場合、最後の 1 バイトは右側を 0 で埋めた 16bit ワードとして扱う
/// - 加算で 16bit からあふれた桁（キャリー）は下位に折り返して足す（1 の補数和）
/// - 最後に全ビットを反転して返す
pub fn compute(bytes: []const u8) u16 {
    var sum: u32 = 0;

    // 2 バイトずつワードとして足し込む
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum += hexdump.readU16(bytes[i..]);
    }

    // 奇数長: 最後の 1 バイトを上位バイトとして扱う（右側 0 パディング）
    if (bytes.len % 2 == 1) {
        sum += @as(u32, bytes[bytes.len - 1]) << 8;
    }

    // キャリーの折り返し。1 回の折り返しで再びあふれることがあるのでループする
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // 1 の補数（全ビット反転）
    return ~@as(u16, @truncate(sum));
}

/// 受信データの検証。チェックサムフィールドを含めたまま全体を計算して
/// 0 になれば正しい。
pub fn verify(bytes: []const u8) bool {
    return compute(bytes) == 0;
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
