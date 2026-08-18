//! IPv4 — ホストからホストへパケットを届ける層 (RFC 791)。
//!
//! Ethernet フレームのペイロードとして運ばれる (EtherType = 0x0800)。
//! ヘッダは可変長で、IHL が長さを申告する:
//!
//!    --- Ethernet Frame with IPv4 packet ---
//!   ┌─ Ethernet header 14 ─┬─ IPv4 header 20〜60 ─┬─ payload ─┬─ padding ─┐
//!   └──────────────────────┴──────────────────────┴───────────┴───────────┘
//!                            IHL がここの長さを     total_length がここまで
//!                            決める                 を決める（padding は範囲外）
//!
//!    --- IPv4 Header (20 byte) ---
//!    0       4       8              16      19                            31
//!   ┌───────┬───────┬───────────────┬───────────────────────────────────────┐
//!   │  ver  │  ihl  │    dscp/ecn   │             total_length              │
//!   ├───────┴───────┴───────────────┼─────┬─────────────────────────────────┤
//!   │        identification         │flags│         fragment_offset         │
//!   ├───────────────┬───────────────┼─────┴─────────────────────────────────┤
//!   │      ttl      │   protocol    │            header_checksum            │
//!   ├───────────────┴───────────────┴───────────────────────────────────────┤
//!   │                             source address                            │
//!   ├───────────────────────────────────────────────────────────────────────┤
//!   │                          destination address                          │
//!   ├───────────────────────────────────────────────────────────────────────┤
//!   │                     options（IHL > 5 のときだけ）                     │
//!   └───────────────────────────────────────────────────────────────────────┘
//!
//! ヘッダに 2 つの長さフィールドがあるのが特徴で、役割が違う:
//!   ihl           ヘッダ自身の長さ。**32bit ワード数**なので 4 倍してバイト数にする
//!   total_length  ヘッダ + ペイロードの合計バイト数
//!
//! ihl がワード数なのは 4 ビットしかないため。1〜15 ワード = 4〜60 バイトを表現でき、
//! 最小の 5 ワード (20 バイト) から 15 ワード (60 バイト) までのオプションを許す。
//! バイト単位にすると 4 ビットでは 15 バイトまでしか数えられず、ヘッダ長に届かない。
//! ヘッダが必ず 4 バイト境界に揃うという副産物もある。
//!
//! チェックサムがヘッダだけを対象にするのは、**経由するルータが毎回書き換えるから**。
//! TTL は 1 ホップごとに減るので、そのたびに再計算が要る。ペイロードまで含めると
//! ルータが全長ぶん再計算することになり、中継のコストが跳ね上がる。
//! ペイロードの完全性は端点だけが気にすればよく、それは L4 (UDP/TCP) の仕事。

const std = @import("std");
const hexdump = @import("hexdump.zig");
const checksum = @import("checksum.zig");
const ethernet = @import("ethernet.zig");
const arp = @import("arp.zig");

pub const header_len_min = 20;
pub const default_ttl = 64;
pub const Addr = [4]u8;
pub const our_addr: Addr = .{ 192, 168, 70, 2 };

/// ペイロードをどの上位層に渡すか。EtherType がフレームに対して果たす役割を、
/// パケットに対して果たす。多重分離の構造は層をまたいで同じ形で繰り返される。
pub const Protocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    _,
};

pub const Packet = struct {
    /// ヘッダ長（**バイト数**）。ワード数のまま持つと使うたびに 4 倍することになり、
    /// 掛け忘れがそのままバグになるので、パースの時点で変換しておく。
    header_len: u8,
    dscp_ecn: u8,
    /// ヘッダ + ペイロードの合計バイト数。
    total_len: u16,
    /// フラグメント再構成のための識別子。同じ元パケットの断片は同じ値を持つ。
    id: u16,
    /// Don't Fragment — 分割せずに送れ。経路 MTU 探索が使う。
    dont_fragment: bool,
    /// More Fragments — 後続の断片がある。最後の断片だけ 0。
    more_fragments: bool,
    /// 元パケット先頭からのオフセット（**8 バイト単位**）。13 ビットしかないため。
    fragment_offset: u16,
    ttl: u8,
    protocol: Protocol,
    checksum: u16,
    src: Addr,
    dst: Addr,
    /// 入力スライスへの参照。total_len で切ってあるので Ethernet のパディングは含まない。
    payload: []const u8,
};

pub const ParseError = error{
    PacketTooShort,
    UnsupportedVersion,
    /// IHL が 5 未満。ヘッダが自分自身より短いことになる。
    InvalidHeaderLength,
    /// total_length がヘッダ長より短い。
    InvalidTotalLength,
    /// 申告された長さぶんのバイトが届いていない。
    Truncated,
    BadChecksum,
};

/// IPv4 パケット（Ethernet ペイロード）をパースする。
///
/// `total_len` を超える分は無視する。ここが **Ethernet の最小フレーム長 (60 バイト) への
/// パディングを剥がす場所**でもある。Ethernet 層には剥がしようがない — フレームの
/// どこまでが本体かを知っているのは、長さを自分で申告している IP だけ。
pub fn parse(bytes: []const u8) ParseError!Packet {
    if (bytes.len < header_len_min) return error.PacketTooShort;
    if (bytes[0] >> 4 != 4) return error.UnsupportedVersion;

    const header_len = (bytes[0] & 0x0f) * 4;
    if (header_len < header_len_min) return error.InvalidHeaderLength;

    const total_len = hexdump.readU16(bytes[2..4]);
    if (total_len < header_len) return error.InvalidTotalLength;

    // 3 段目: 申告ぶんのバイトが実際に届いているか
    if (bytes.len < total_len) return error.Truncated;

    // チェックサムはヘッダのみが対象。フィールドを含めたまま計算して 0 になれば正しい
    if (!checksum.verify(bytes[0..header_len])) return error.BadChecksum;

    const flags_and_offset = hexdump.readU16(bytes[6..8]);

    return .{
        .header_len = header_len,
        .dscp_ecn = bytes[1],
        .total_len = total_len,
        .id = hexdump.readU16(bytes[4..6]),
        // 上位 3 ビットがフラグ。最上位は予約で常に 0
        .dont_fragment = flags_and_offset & 0x4000 != 0,
        .more_fragments = flags_and_offset & 0x2000 != 0,
        .fragment_offset = flags_and_offset & 0x1fff,
        .ttl = bytes[8],
        .protocol = @enumFromInt(bytes[9]),
        .checksum = hexdump.readU16(bytes[10..12]),
        .src = bytes[12..16].*,
        .dst = bytes[16..20].*,
        // オプションを飛ばして本体だけ、かつ末尾のパディングは切り落とす
        .payload = bytes[header_len..total_len],
    };
}

/// 自分宛のパケットか
pub fn isForUs(packet: Packet) bool {
    return std.mem.eql(u8, &packet.dst, &our_addr);
}

pub const BuildError = error{ BufferTooSmall, PayloadTooLarge };

/// IPv4 パケットをバイト列に組み立てる
pub fn build(buf: []u8, dst: Addr, protocol: Protocol, payload: []const u8) BuildError![]u8 {
    const total_len = header_len_min + payload.len;
    if (total_len > ethernet.mtu) return error.PayloadTooLarge;
    if (buf.len < total_len) return error.BufferTooSmall;

    buf[0] = 0x45; // バージョン 4、IHL 5 ワード = 20 バイト
    buf[1] = 0; // DSCP / ECN — 経路上でほぼ無視されるので 0
    hexdump.writeU16(buf[2..4], @intCast(total_len));
    hexdump.writeU16(buf[4..6], 0); // 識別子
    hexdump.writeU16(buf[6..8], 0x4000); // DF を立てる、フラグメントオフセット 0
    buf[8] = default_ttl;
    buf[9] = @intFromEnum(protocol);
    hexdump.writeU16(buf[10..12], 0); // チェックサムは 0 埋めしてから計算する
    @memcpy(buf[12..16], &our_addr);
    @memcpy(buf[16..20], &dst);

    // 全フィールドを書き終えてから計算する。0 のまま計算した結果を書き戻すと、
    // 「フィールドを含めたまま全体を計算すると 0 になる」性質が成立する
    hexdump.writeU16(buf[10..12], checksum.compute(buf[0..header_len_min]));

    @memcpy(buf[header_len_min..total_len], payload);
    return buf[0..total_len];
}

/// 送信要求 1 件の結末
pub const Outcome = enum {
    /// 宛先 MAC が分かったので、IPv4 パケットを載せたフレームができた。
    sent,
    /// 宛先 MAC が未解決なので、代わりに ARP 要求ができた。payload は捨てている。
    resolving,
};

/// `dst` 宛に `payload` を送るフレームを組み立てる。**外に出る経路はここ 1 本**。
pub fn send(
    buf: []u8,
    table: *const arp.Table,
    dst: Addr,
    protocol: Protocol,
    payload: []const u8,
) !struct { Outcome, []u8 } {
    const dst_mac = table.lookup(dst) orelse {
        var arp_buf: [arp.packet_len]u8 = undefined;
        return .{ .resolving, try ethernet.build(buf, .{
            .dst = ethernet.broadcast,
            .src = ethernet.our_mac,
            .ethertype = .arp,
            .payload = try arp.build(&arp_buf, arp.requestFor(dst)),
        }) };
    };

    var packet_buf: [ethernet.mtu]u8 = undefined;
    return .{ .sent, try ethernet.build(buf, .{
        .dst = dst_mac,
        .src = ethernet.our_mac,
        .ethertype = .ip4,
        .payload = try build(&packet_buf, dst, protocol, payload),
    }) };
}

pub fn formatAddr(writer: *std.Io.Writer, addr: Addr) std.Io.Writer.Error!void {
    try writer.print("{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] });
}

const sample_echo_request = [_]u8{
    // --- IPv4 ヘッダ 20 バイト ---
    0x45, // バージョン 4、IHL 5 ワード = 20 バイト
    0x00, // DSCP / ECN
    0x00, 0x54, // 全長 84 = ヘッダ 20 + ICMP 64
    0xa3, 0x69, // 識別子
    0x40, 0x00, // フラグ: DF、フラグメントオフセット 0
    0x40, // TTL 64
    0x01, // プロトコル: ICMP
    0x89, 0xeb, // ヘッダチェックサム
    0xc0, 0xa8, 0x46, 0x01, // 送信元 192.168.70.1（カーネル側）
    0xc0, 0xa8, 0x46, 0x02, // 宛先 192.168.70.2（このスタック）

    // --- ICMP 64 バイト（Step 11 で扱う）---
    0x08, 0x00, // タイプ 8 = Echo Request、コード 0
    0x8f, 0xda, // チェックサム
    0x00, 0x09, // 識別子
    0x00, 0x01, // シーケンス番号
    0x86, 0x3b, 0x81, 0x6a, 0x00, 0x00, 0x00, 0x00, // 送信時刻
    0x00, 0x00, 0x98, 0xa2, 0x09, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, // 以降は ping が詰める既定パターン
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
    0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37,
};

test "実際の echo request をパースする" {
    const packet = try parse(&sample_echo_request);

    try std.testing.expectEqual(@as(u8, 20), packet.header_len);
    try std.testing.expectEqual(@as(u16, 84), packet.total_len);
    try std.testing.expectEqual(@as(u16, 0xa369), packet.id);
    try std.testing.expectEqual(@as(u8, 64), packet.ttl);
    try std.testing.expectEqual(Protocol.icmp, packet.protocol);
    try std.testing.expectEqual(Addr{ 192, 168, 70, 1 }, packet.src);
    try std.testing.expectEqual(Addr{ 192, 168, 70, 2 }, packet.dst);

    // DF は立っているが、分割されてはいない
    try std.testing.expect(packet.dont_fragment);
    try std.testing.expect(!packet.more_fragments);
    try std.testing.expectEqual(@as(u16, 0), packet.fragment_offset);

    // ペイロードは ICMP の 64 バイト。先頭はタイプ 8 = Echo Request
    try std.testing.expectEqual(@as(usize, 64), packet.payload.len);
    try std.testing.expectEqual(@as(u8, 8), packet.payload[0]);
}

test "ペイロードは入力スライスへの参照" {
    const packet = try parse(&sample_echo_request);
    try std.testing.expectEqual(
        @intFromPtr(&sample_echo_request[20]),
        @intFromPtr(packet.payload.ptr),
    );
}

test "1 バイト壊すとチェックサム検証が落ちる" {
    var bytes = sample_echo_request;
    bytes[8] = 63; // TTL を 64 → 63（ルータが 1 減らしたのに再計算しなかった状態）
    try std.testing.expectError(error.BadChecksum, parse(&bytes));

    // ペイロードを壊しても落ちない — 検証対象はヘッダだけ
    bytes = sample_echo_request;
    bytes[40] = 0xff;
    _ = try parse(&bytes);
}

test "最小フレーム長のパディングを剥がすのは IP" {
    // 全長 28 バイト（ヘッダ 20 + ペイロード 8）のパケットを作る。
    // Ethernet の最小ペイロード長 46 に届かないので、実 NIC 経由なら 18 バイト詰められる。
    var bytes: [46]u8 = @splat(0);
    @memcpy(bytes[0..20], sample_echo_request[0..20]);
    hexdump.writeU16(bytes[2..4], 28); // 全長を書き換える
    hexdump.writeU16(bytes[10..12], 0); // チェックサムを 0 にして計算し直す
    hexdump.writeU16(bytes[10..12], checksum.compute(bytes[0..20]));

    const packet = try parse(&bytes);
    // 入力は 46 バイトあるが、ペイロードは 8 バイトに切られる
    try std.testing.expectEqual(@as(usize, 8), packet.payload.len);
}

test "IHL が 5 未満なら弾く" {
    var bytes = sample_echo_request;
    bytes[0] = 0x44; // バージョン 4、IHL 4 ワード = 16 バイト（ヘッダより短い）
    try std.testing.expectError(error.InvalidHeaderLength, parse(&bytes));
}

test "IPv4 以外は弾く" {
    var bytes = sample_echo_request;
    bytes[0] = 0x65; // バージョン 6
    try std.testing.expectError(error.UnsupportedVersion, parse(&bytes));
}

test "短すぎる入力と、申告より短い入力" {
    try std.testing.expectError(error.PacketTooShort, parse(&.{}));
    try std.testing.expectError(error.PacketTooShort, parse(sample_echo_request[0..19]));
    // ヘッダは揃っているが、全長 84 に対して本体が足りない
    try std.testing.expectError(error.Truncated, parse(sample_echo_request[0..83]));
}

test "全長がヘッダ長より短ければ弾く" {
    var bytes = sample_echo_request;
    hexdump.writeU16(bytes[2..4], 19); // ヘッダ 20 バイトより短い全長
    hexdump.writeU16(bytes[10..12], 0);
    hexdump.writeU16(bytes[10..12], checksum.compute(bytes[0..20]));
    try std.testing.expectError(error.InvalidTotalLength, parse(&bytes));
}

test "オプション付きヘッダではペイロードの開始位置がずれる" {
    // IHL 6 ワード = 24 バイト。オプション 4 バイトぶん本体が後ろにずれる
    var bytes: [88]u8 = undefined;
    @memcpy(bytes[0..20], sample_echo_request[0..20]);
    @memset(bytes[20..24], 0x01); // オプション: NOP を 4 つ
    @memcpy(bytes[24..88], sample_echo_request[20..84]);

    bytes[0] = 0x46; // IHL 6
    hexdump.writeU16(bytes[2..4], 88); // 全長 = 24 + 64
    hexdump.writeU16(bytes[10..12], 0);
    hexdump.writeU16(bytes[10..12], checksum.compute(bytes[0..24]));

    const packet = try parse(&bytes);
    try std.testing.expectEqual(@as(u8, 24), packet.header_len);
    try std.testing.expectEqual(@as(usize, 64), packet.payload.len);
    try std.testing.expectEqual(@as(u8, 8), packet.payload[0]); // ICMP タイプ 8
}

test "未知のプロトコル番号も値を保持する" {
    var bytes = sample_echo_request;
    bytes[9] = 89; // OSPF
    hexdump.writeU16(bytes[10..12], 0);
    hexdump.writeU16(bytes[10..12], checksum.compute(bytes[0..20]));

    const packet = try parse(&bytes);
    try std.testing.expectEqual(@as(u8, 89), @intFromEnum(packet.protocol));
}

test "宛先が自分かどうかの判断はパースと分かれている" {
    const packet = try parse(&sample_echo_request);
    try std.testing.expect(isForUs(packet));

    var bytes = sample_echo_request;
    bytes[19] = 9; // 宛先を 192.168.70.9 に
    hexdump.writeU16(bytes[10..12], 0);
    hexdump.writeU16(bytes[10..12], checksum.compute(bytes[0..20]));

    // パース自体は成功する。正しいパケットではあるので
    const other = try parse(&bytes);
    try std.testing.expect(!isForUs(other));
}

test "組み立てたヘッダは自分でパースし直せる" {
    var buf: [64]u8 = undefined;
    const bytes = try build(&buf, .{ 192, 168, 70, 1 }, .icmp, "hello");

    try std.testing.expectEqual(@as(usize, 25), bytes.len); // ヘッダ 20 + 5

    const packet = try parse(bytes);
    try std.testing.expectEqual(@as(u8, 20), packet.header_len);
    try std.testing.expectEqual(@as(u16, 25), packet.total_len);
    try std.testing.expectEqual(Protocol.icmp, packet.protocol);
    try std.testing.expectEqual(our_addr, packet.src);
    try std.testing.expectEqual(Addr{ 192, 168, 70, 1 }, packet.dst);
    try std.testing.expectEqual(@as(u8, default_ttl), packet.ttl);
    try std.testing.expectEqualStrings("hello", packet.payload);

    // 分割しないので DF を立て、識別子は使わない (RFC 6864)
    try std.testing.expect(packet.dont_fragment);
    try std.testing.expect(!packet.more_fragments);
    try std.testing.expectEqual(@as(u16, 0), packet.id);
}

test "組み立てたヘッダのチェックサムは検証を通る" {
    var buf: [64]u8 = undefined;
    const bytes = try build(&buf, .{ 192, 168, 70, 1 }, .icmp, "hello");
    // tcpdump -vv が bad cksum を出さない条件そのもの
    try std.testing.expect(checksum.verify(bytes[0..20]));
}

test "MTU を超えるペイロードは組み立てられない" {
    var buf: [2048]u8 = undefined;
    const ok: [ethernet.mtu - header_len_min]u8 = @splat(0); // ちょうど収まる
    _ = try build(&buf, .{ 192, 168, 70, 1 }, .icmp, &ok);

    const too_big: [ethernet.mtu - header_len_min + 1]u8 = @splat(0);
    try std.testing.expectError(
        error.PayloadTooLarge,
        build(&buf, .{ 192, 168, 70, 1 }, .icmp, &too_big),
    );
}

const kernel_addr: Addr = .{ 192, 168, 70, 1 };
const kernel_mac: ethernet.Mac = .{ 0xce, 0xbd, 0x84, 0x58, 0x71, 0x32 };

test "解決済みの IP は即フレームになる" {
    var table: arp.Table = .{};
    table.put(kernel_addr, kernel_mac);

    var buf: [ethernet.max_frame_len]u8 = undefined;
    const outcome, const bytes = try send(&buf, &table, kernel_addr, .icmp, "hello");
    try std.testing.expectEqual(Outcome.sent, outcome);

    const frame = try ethernet.parse(bytes);
    try std.testing.expectEqual(kernel_mac, frame.dst); // ブロードキャストではない
    try std.testing.expectEqual(ethernet.EtherType.ip4, frame.ethertype);

    const packet = try parse(frame.payload);
    try std.testing.expectEqualStrings("hello", packet.payload);
}

test "未解決の IP は ARP 要求になり、payload は捨てられる" {
    var table: arp.Table = .{};

    var buf: [ethernet.max_frame_len]u8 = undefined;
    const outcome, const bytes = try send(&buf, &table, kernel_addr, .icmp, "hello");
    // できたのは ARP 要求。payload を載せたフレームは出ていない
    try std.testing.expectEqual(Outcome.resolving, outcome);

    const frame = try ethernet.parse(bytes);
    try std.testing.expectEqual(ethernet.broadcast, frame.dst);
    try std.testing.expectEqual(ethernet.EtherType.arp, frame.ethertype);

    const request = try arp.parse(frame.payload);
    try std.testing.expectEqual(arp.Oper.request, request.oper);
    try std.testing.expectEqual(kernel_addr, request.target_ip);
}

test "応答を学習すれば次は送れる" {
    var table: arp.Table = .{};
    var buf: [ethernet.max_frame_len]u8 = undefined;

    {
        const outcome, const bytes = try send(&buf, &table, kernel_addr, .icmp, "hi");
        try std.testing.expectEqual(Outcome.resolving, outcome);
        try std.testing.expectEqual(ethernet.EtherType.arp, (try ethernet.parse(bytes)).ethertype);
    }

    table.put(kernel_addr, kernel_mac); // ARP 応答を受け取ったとして学習

    {
        const outcome, const bytes = try send(&buf, &table, kernel_addr, .icmp, "hi");
        try std.testing.expectEqual(Outcome.sent, outcome);
        try std.testing.expectEqual(ethernet.EtherType.ip4, (try ethernet.parse(bytes)).ethertype);
    }
}

test "formatAddr" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try formatAddr(&w, .{ 192, 168, 70, 2 });
    try std.testing.expectEqualStrings("192.168.70.2", w.buffered());
}
