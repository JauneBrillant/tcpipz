//! ICMP — IP 層の制御メッセージ (RFC 792)。
//!
//! IPv4 パケットのペイロードとして運ばれる（プロトコル番号 1）。
//! 「L4」の位置にいるのにポート番号を持たない — 宛先はホストであって、
//! ホスト上のプロセスではないから。TCP / UDP が「どのアプリへ」を運ぶのに対し、
//! ICMP は「IP 層そのものへの報告」を運ぶ。到達不能、TTL 切れ、そして疎通確認。
//!
//!    --- IPv4 パケットに載った ICMP ---
//!   ┌─ IPv4 header 20 ─┬─ ICMP header 8 ─┬─ data ─┐
//!   └──────────────────┴─────────────────┴────────┘
//!                        ↑ チェックサムはここから末尾まで全部が対象
//!
//!    --- ICMP Echo ヘッダ 8 バイト ---
//!    0               8              16                              31
//!   ┌───────────────┬───────────────┬───────────────────────────────┐
//!   │     type      │     code      │            checksum           │
//!   ├───────────────┴───────────────┼───────────────────────────────┤
//!   │          identifier           │        sequence number        │
//!   ├───────────────────────────────┴───────────────────────────────┤
//!   │                             data...                           │
//!   └───────────────────────────────────────────────────────────────┘
//!
//! 先頭 4 バイト (type / code / checksum) は全メッセージ共通だが、**続く 4 バイトは
//! タイプごとに意味が違う**（RFC 792 では "rest of header"）。Echo では識別子と
//! シーケンス番号、到達不能では未使用の 0、リダイレクトではゲートウェイの IP になる。
//! ここでは Echo だけを解釈する。
//!
//! チェックサムが IPv4 と違ってメッセージ全体を対象にするのは、**途中のルータが
//! 書き換えないから**。IPv4 ヘッダは TTL が 1 ホップごとに減るのでヘッダだけを
//! 対象にして再計算を軽くしているが、ICMP の中身は端から端まで不変。
//! 疑似ヘッダが無いのも ICMP の特徴で、ここは UDP / TCP と違う。

const std = @import("std");
const hexdump = @import("hexdump.zig");
const checksum = @import("checksum.zig");

/// type / code / checksum / rest of header で 8 バイト。
pub const header_len = 8;

pub const Type = enum(u8) {
    echo_reply = 0,
    echo_request = 8,
    _,
};

pub const Message = struct {
    type: Type,
    code: u8,
    checksum: u16,
    /// Echo の識別子。`ping` は自分の PID などを入れておき、返ってきた応答が
    /// 自分の投げたものかを判定する。ポート番号を持たない ICMP で、
    /// 「どのプロセス宛か」を成立させているのがこのフィールド。
    id: u16,
    /// Echo のシーケンス番号。1 発ごとに増える。ping の `icmp_seq=` の値そのもので、
    /// どれが落ちたか・順序が入れ替わったかがこれで分かる。
    seq: u16,
    /// data 部。Echo Request はここに任意のバイト列を詰められ、
    /// Echo Reply はそれをそのまま返す義務がある (RFC 792)。
    /// Linux の ping は先頭に送信時刻を入れ、残りを 0x10, 0x11, ... で埋める。
    payload: []const u8,
};

pub const ParseError = error{
    MessageTooShort,
    BadChecksum,
};

/// ICMP メッセージ（IPv4 のペイロード）をパースする。
///
/// `id` / `seq` は Echo 系でのみ意味を持つ。他のタイプでは "rest of header" の
/// 解釈違いなので、`type` を見ずに読んではいけない。
pub fn parse(bytes: []const u8) ParseError!Message {
    if (bytes.len < header_len) return error.MessageTooShort;

    // 検証対象はメッセージ全体。IPv4 と違い data も含む
    if (!checksum.verify(bytes)) return error.BadChecksum;

    return .{
        .type = @enumFromInt(bytes[0]),
        .code = bytes[1],
        .checksum = hexdump.readU16(bytes[2..4]),
        .id = hexdump.readU16(bytes[4..6]),
        .seq = hexdump.readU16(bytes[6..8]),
        .payload = bytes[header_len..],
    };
}

pub const BuildError = error{BufferTooSmall};

/// ICMP メッセージをバイト列に組み立てる
///
/// `Message.checksum` は無視して計算し直す。受信したものを組み立て直す以上、
/// 元の値には意味が無い — 中身を 1 ビットでも変えれば別の値になる。
pub fn build(buf: []u8, message: Message) BuildError![]u8 {
    const total_len = header_len + message.payload.len;
    if (buf.len < total_len) return error.BufferTooSmall;

    buf[0] = @intFromEnum(message.type);
    buf[1] = message.code;
    hexdump.writeU16(buf[2..4], 0); // チェックサムは 0 埋めしてから計算する
    hexdump.writeU16(buf[4..6], message.id);
    hexdump.writeU16(buf[6..8], message.seq);
    @memcpy(buf[header_len..total_len], message.payload);

    // data を書き終えてから全体を計算する。IPv4 と違い対象はメッセージ全体
    hexdump.writeU16(buf[2..4], checksum.compute(buf[0..total_len]));

    return buf[0..total_len];
}

/// Echo Request に対する Echo Reply を作る。
///
/// 変えるのはタイプだけ。id / seq / data をそのまま返すのは RFC 792 の要求で、
/// 送信側はこれを頼りに「自分が投げたどの 1 発への応答か」を判定し、
/// data に埋めておいた送信時刻との差から RTT を出す。
pub fn replyTo(request: Message) Message {
    return .{
        .type = .echo_reply,
        .code = 0,
        .checksum = 0, // build が計算し直す
        .id = request.id,
        .seq = request.seq,
        .payload = request.payload,
    };
}

// tcpdump -i tap0 -xx -c1 icmp で採取した `ping -c2 192.168.70.2` の 1 発目から、
// ICMP 部分の 64 バイト（IPv4 ヘッダ 20 バイトを除いたもの）。
const sample_echo_request = [_]u8{
    0x08, 0x00, // タイプ 8 = Echo Request、コード 0
    0x8f, 0xda, // チェックサム
    0x00, 0x09, // 識別子
    0x00, 0x01, // シーケンス番号
    0x86, 0x3b, 0x81, 0x6a, 0x00, 0x00, 0x00, 0x00, // 送信時刻 tv_sec  = 1786854278
    0x98, 0xa2, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, //          tv_usec = 631448
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // 以降は ping が詰める既定パターン
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};

test "実際の echo request をパースする" {
    const message = try parse(&sample_echo_request);

    try std.testing.expectEqual(Type.echo_request, message.type);
    try std.testing.expectEqual(@as(u8, 0), message.code);
    try std.testing.expectEqual(@as(u16, 9), message.id);
    try std.testing.expectEqual(@as(u16, 1), message.seq);

    // ping -c2 の既定は 56 バイト。ここに ICMP ヘッダ 8 を足した 64 が
    // IPv4 の total_len 84 からヘッダ 20 を引いた値と一致する
    try std.testing.expectEqual(@as(usize, 56), message.payload.len);
    try std.testing.expectEqual(@as(u8, 0x86), message.payload[0]);
}

test "payload は入力スライスへの参照" {
    const message = try parse(&sample_echo_request);
    try std.testing.expectEqual(
        @intFromPtr(&sample_echo_request[header_len]),
        @intFromPtr(message.payload.ptr),
    );
}

test "data を壊してもチェックサム検証が落ちる" {
    // IPv4 との対比。IPv4 はヘッダだけが対象なのでペイロードを壊しても通るが、
    // ICMP は data まで含めて計算するので落ちる
    var bytes = sample_echo_request;
    bytes[40] = 0xff;
    try std.testing.expectError(error.BadChecksum, parse(&bytes));

    // ヘッダ側を壊しても当然落ちる
    bytes = sample_echo_request;
    bytes[5] = 0x0a; // 識別子 9 → 10
    try std.testing.expectError(error.BadChecksum, parse(&bytes));
}

test "ヘッダに満たない入力はエラー" {
    try std.testing.expectError(error.MessageTooShort, parse(&.{}));
    try std.testing.expectError(error.MessageTooShort, parse(sample_echo_request[0..7]));
}

test "data が空でもパースできる" {
    // Echo の data は任意長で、0 バイトでも成立する
    var bytes = [_]u8{ 0x08, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x01 };
    hexdump.writeU16(bytes[2..4], checksum.compute(&bytes));

    const message = try parse(&bytes);
    try std.testing.expectEqual(Type.echo_request, message.type);
    try std.testing.expectEqual(@as(usize, 0), message.payload.len);
}

test "未知のタイプも値を保持できる" {
    var bytes = sample_echo_request;
    bytes[0] = 3; // Destination Unreachable
    hexdump.writeU16(bytes[2..4], 0);
    hexdump.writeU16(bytes[2..4], checksum.compute(&bytes));

    const message = try parse(&bytes);
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(message.type));
}

test "Echo Request から Echo Reply を組み立てる" {
    const request = try parse(&sample_echo_request);

    var buf: [64]u8 = undefined;
    const bytes = try build(&buf, replyTo(request));

    // 長さは変わらない。data をそのまま返すので
    try std.testing.expectEqual(sample_echo_request.len, bytes.len);

    const reply = try parse(bytes); // parse を通る = チェックサムが正しい
    try std.testing.expectEqual(Type.echo_reply, reply.type);
    try std.testing.expectEqual(@as(u8, 0), reply.code);
    try std.testing.expectEqual(request.id, reply.id);
    try std.testing.expectEqual(request.seq, reply.seq);
    try std.testing.expectEqualSlices(u8, request.payload, reply.payload);
}

test "タイプ以外のバイトは 1 つも変わらない" {
    const request = try parse(&sample_echo_request);

    var buf: [64]u8 = undefined;
    const bytes = try build(&buf, replyTo(request));

    // 違うのはタイプ (0 バイト目) とチェックサム (2〜3 バイト目) だけ
    try std.testing.expectEqual(@as(u8, 0), bytes[0]);
    try std.testing.expectEqualSlices(u8, sample_echo_request[4..], bytes[4..]);

    // タイプが 8 → 0 に減った分、チェックサムは 0x0800 増える。
    // 1 の補数和の一部を減らせば、その補数は同じだけ増えるため
    const before = hexdump.readU16(sample_echo_request[2..4]);
    const after = hexdump.readU16(bytes[2..4]);
    try std.testing.expectEqual(before + 0x0800, after);
}

test "build した結果を parse で戻せる" {
    var buf: [16]u8 = undefined;
    const original: Message = .{
        .type = .echo_reply,
        .code = 0,
        .checksum = 0,
        .id = 0x1234,
        .seq = 7,
        .payload = "hello",
    };
    const parsed = try parse(try build(&buf, original));

    try std.testing.expectEqual(original.type, parsed.type);
    try std.testing.expectEqual(original.id, parsed.id);
    try std.testing.expectEqual(original.seq, parsed.seq);
    try std.testing.expectEqualStrings(original.payload, parsed.payload);
}

test "バッファが足りなければエラー" {
    // ヘッダ 8 + data 5 = 13 バイト必要
    var buf: [12]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, build(&buf, .{
        .type = .echo_reply,
        .code = 0,
        .checksum = 0,
        .id = 1,
        .seq = 1,
        .payload = "hello",
    }));
}
