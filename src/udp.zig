//! UDP — IP にポート番号を足しただけの L4 (RFC 768)
//!
//! IPv4 パケットのペイロードとして運ばれる（プロトコル番号 17）
//! IP が「どのホストへ」を運ぶのに対し、UDP が足すのは「そのホストのどのプロセスへ」
//!
//!    --- IPv4 パケットに載った UDP ---
//!   ┌─ IPv4 header 20 ─┬─ UDP header 8 ─┬─ payload ─┐
//!   └──────────────────┴────────────────┴───────────┘
//!                        ↑ チェックサムは疑似ヘッダ + ここから末尾まで
//!
//!    --- UDP ヘッダ 8 バイト ---
//!    0                              16                              31
//!   ┌───────────────────────────────┬───────────────────────────────┐
//!   │          source port          │       destination port        │
//!   ├───────────────────────────────┼───────────────────────────────┤
//!   │            length             │           checksum            │
//!   ├───────────────────────────────┴───────────────────────────────┤
//!   │                            payload                            │
//!   └───────────────────────────────────────────────────────────────┘

const std = @import("std");
const hexdump = @import("hexdump.zig");
const checksum = @import("checksum.zig");
const ip = @import("ip.zig");

pub const header_len = 8;

pub const Datagram = struct {
    src_port: u16,
    dst_port: u16,
    /// ヘッダ + ペイロードの合計バイト数
    length: u16,
    /// 0 は「送信側が計算しなかった」の意味。値そのものに意味は無いが、
    /// 未計算かどうかを呼び出し側が知れるように残しておく
    checksum: u16,
    payload: []const u8,
};

pub const ParseError = error{
    DatagramTooShort,
    /// length がヘッダ長 8 未満。データグラムが自分自身より短いことになる
    InvalidLength,
    /// 申告された長さぶんのバイトが届いていない
    Truncated,
    BadChecksum,
};

/// UDP データグラムをパースする
///
/// 送信元 / 宛先 IP を要求するのは疑似ヘッダのため。L4 のパーサが L3 の情報を
/// 引数に取るのは層の分離としては歪だが、UDP / TCP のチェックサムはそう定義されている
pub fn parse(bytes: []const u8, src: ip.Addr, dst: ip.Addr) ParseError!Datagram {
    if (bytes.len < header_len) return error.DatagramTooShort;

    const length = hexdump.readU16(bytes[4..6]);
    if (length < header_len) return error.InvalidLength;
    if (bytes.len < length) return error.Truncated;

    const datagram = bytes[0..length];
    const sum = hexdump.readU16(bytes[6..8]);

    // IPv4 ではチェックサムは任意。0 は「未計算」なので検証しない。
    // TAP デバイス相手だとカーネルがオフロード前提で 0 のまま流してくることがある
    // （entrypoint.sh の `ethtool -K tap0 tx off` はこれを止めている）
    if (sum != 0 and !checksum.verifyWithPseudo(pseudoFor(src, dst, length), datagram)) {
        return error.BadChecksum;
    }

    return .{
        .src_port = hexdump.readU16(bytes[0..2]),
        .dst_port = hexdump.readU16(bytes[2..4]),
        .length = length,
        .checksum = sum,
        .payload = datagram[header_len..],
    };
}

pub const BuildError = error{ BufferTooSmall, PayloadTooLarge };

/// UDP データグラムをバイト列に組み立てる
pub fn build(
    buf: []u8,
    dst: ip.Addr,
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
) BuildError![]u8 {
    const total_len = header_len + payload.len;
    if (total_len > std.math.maxInt(u16)) return error.PayloadTooLarge;
    if (buf.len < total_len) return error.BufferTooSmall;

    hexdump.writeU16(buf[0..2], src_port);
    hexdump.writeU16(buf[2..4], dst_port);
    hexdump.writeU16(buf[4..6], @intCast(total_len));
    hexdump.writeU16(buf[6..8], 0); // チェックサムは 0 埋めしてから計算する
    @memcpy(buf[header_len..total_len], payload);

    const sum = checksum.computeWithPseudo(
        pseudoFor(ip.our_addr, dst, @intCast(total_len)),
        buf[0..total_len],
    );

    // 計算結果が 0 になったら 0xffff を送る。0 は「未計算」の意味に予約されているため。
    // 1 の補数では -0 (0xffff) と +0 (0x0000) がどちらもゼロなので、
    // 受信側がどちらで検証しても結果は変わらない
    hexdump.writeU16(buf[6..8], if (sum == 0) 0xffff else sum);

    return buf[0..total_len];
}

/// この UDP データグラム用の疑似ヘッダ。プロトコル番号は 17 で固定
fn pseudoFor(src: ip.Addr, dst: ip.Addr, length: u16) [checksum.pseudo_header_len]u8 {
    return checksum.pseudoHeader(src, dst, @intFromEnum(ip.Protocol.udp), length);
}

// tcpdump -i tap0 -xx -c1 'udp and dst port 7' で採取した
// `echo -n hello | nc -u 192.168.70.2 7` の UDP 部分（IPv4 ヘッダ 20 バイトを除いたもの）。
const sample_src: ip.Addr = .{ 192, 168, 70, 1 };
const sample_dst: ip.Addr = .{ 192, 168, 70, 2 };
const sample_datagram = [_]u8{
    0xa6, 0x89, // 送信元ポート 42633（カーネルが割り当てたエフェメラルポート）
    0x00, 0x07, // 宛先ポート 7 (echo)
    0x00, 0x0d, // 長さ 13 = ヘッダ 8 + "hello" 5
    0x08, 0x1d, // チェックサム（疑似ヘッダ込み）
    'h',  'e',
    'l',  'l',
    'o',
};

test "実際の UDP データグラムをパースする" {
    const datagram = try parse(&sample_datagram, sample_src, sample_dst);

    try std.testing.expectEqual(@as(u16, 42633), datagram.src_port);
    try std.testing.expectEqual(@as(u16, 7), datagram.dst_port);
    try std.testing.expectEqual(@as(u16, 13), datagram.length);
    try std.testing.expectEqualStrings("hello", datagram.payload);

    // length はヘッダを含む。data の長さはそこから 8 引いた値
    try std.testing.expectEqual(datagram.length - header_len, datagram.payload.len);
}

test "payload は入力スライスへの参照" {
    const datagram = try parse(&sample_datagram, sample_src, sample_dst);
    try std.testing.expectEqual(
        @intFromPtr(&sample_datagram[header_len]),
        @intFromPtr(datagram.payload.ptr),
    );
}

test "宛先 IP が違えばチェックサムが落ちる" {
    // 疑似ヘッダの意義。バイト列は 1 ビットも変わっていないのに、
    // 「本来この宛先に届くはずではなかった」ことを L4 が検出できる
    try std.testing.expectError(
        error.BadChecksum,
        parse(&sample_datagram, sample_src, .{ 192, 168, 70, 9 }),
    );
    try std.testing.expectError(
        error.BadChecksum,
        parse(&sample_datagram, .{ 10, 0, 0, 1 }, sample_dst),
    );
}

test "data を壊すとチェックサムが落ちる" {
    var bytes = sample_datagram;
    bytes[10] = 'X';
    try std.testing.expectError(error.BadChecksum, parse(&bytes, sample_src, sample_dst));
}

test "チェックサム 0 は未計算なので検証しない" {
    var bytes = sample_datagram;
    hexdump.writeU16(bytes[6..8], 0);
    bytes[8] = 'X'; // 中身を壊しても通ってしまう

    const datagram = try parse(&bytes, sample_src, sample_dst);
    try std.testing.expectEqual(@as(u16, 0), datagram.checksum);
    try std.testing.expectEqualStrings("Xello", datagram.payload);
}

test "ヘッダに満たない入力はエラー" {
    try std.testing.expectError(error.DatagramTooShort, parse(&.{}, sample_src, sample_dst));
    try std.testing.expectError(
        error.DatagramTooShort,
        parse(sample_datagram[0..7], sample_src, sample_dst),
    );
}

test "length が不正な入力はエラー" {
    var bytes = sample_datagram;

    hexdump.writeU16(bytes[4..6], 7); // ヘッダ長より短い
    try std.testing.expectError(error.InvalidLength, parse(&bytes, sample_src, sample_dst));

    hexdump.writeU16(bytes[4..6], 14); // 届いているバイト数より長い
    try std.testing.expectError(error.Truncated, parse(&bytes, sample_src, sample_dst));
}

test "data が空でもパースできる" {
    // ヘッダだけの UDP は正当。nc -u で改行なしの空入力を送るとこうなる
    var bytes = [_]u8{ 0xa6, 0x89, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00 };
    hexdump.writeU16(bytes[6..8], checksum.computeWithPseudo(
        pseudoFor(sample_src, sample_dst, 8),
        &bytes,
    ));

    const datagram = try parse(&bytes, sample_src, sample_dst);
    try std.testing.expectEqual(@as(usize, 0), datagram.payload.len);
}

test "申告より長い入力は length で切られる" {
    // Ethernet の 60 バイトパディングは IP 層で落ちるが、UDP も自分の長さを持っている
    var bytes: [16]u8 = undefined;
    @memcpy(bytes[0..sample_datagram.len], &sample_datagram);
    @memset(bytes[sample_datagram.len..], 0xff);

    const datagram = try parse(&bytes, sample_src, sample_dst);
    try std.testing.expectEqualStrings("hello", datagram.payload);
}

test "組み立てたものをパースで戻せる" {
    var buf: [32]u8 = undefined;
    const bytes = try build(&buf, sample_src, 7, 42633, "hello");

    // 送信側は our_addr。受信側から見た src / dst はこの向きになる
    const datagram = try parse(bytes, ip.our_addr, sample_src);
    try std.testing.expectEqual(@as(u16, 7), datagram.src_port);
    try std.testing.expectEqual(@as(u16, 42633), datagram.dst_port);
    try std.testing.expectEqual(@as(u16, 13), datagram.length);
    try std.testing.expectEqualStrings("hello", datagram.payload);
}

test "エコー応答ではポートが入れ替わる" {
    const request = try parse(&sample_datagram, sample_src, sample_dst);

    var buf: [32]u8 = undefined;
    const bytes = try build(&buf, sample_src, request.dst_port, request.src_port, request.payload);
    const reply = try parse(bytes, ip.our_addr, sample_src);

    // 行きの宛先が帰りの送信元になる。IP アドレスと同じ入れ替えがポートでも起きる
    try std.testing.expectEqual(request.dst_port, reply.src_port);
    try std.testing.expectEqual(request.src_port, reply.dst_port);
    try std.testing.expectEqualStrings(request.payload, reply.payload);
}

test "チェックサムが 0 になる場合は 0xffff を送る" {
    // 総当たりで見つけた、計算結果がちょうど 0 になる組み合わせ
    var buf: [16]u8 = undefined;
    const bytes = try build(&buf, sample_src, 7, 1024, &.{ 0xee, 0x7e });

    try std.testing.expectEqual(@as(u16, 0xffff), hexdump.readU16(bytes[6..8]));

    // 0xffff でも検証は通る。1 の補数和では 0xffff を足すことがゼロを足すことに等しい
    _ = try parse(bytes, ip.our_addr, sample_src);
}

test "バッファが足りなければエラー" {
    // ヘッダ 8 + data 5 = 13 バイト必要
    var buf: [12]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, build(&buf, sample_src, 7, 7, "hello"));
}
