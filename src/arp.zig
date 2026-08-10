//! ARP — IPv4 アドレスから MAC アドレスを引く (RFC 826)。
//!
//! ARP 自体は汎用のアドレス解決プロトコルで、ハードウェア種別・プロトコル種別・
//! アドレス長のフィールドで任意の L2/L3 の組み合わせを表現できる。
//! このスタックでは Ethernet (MAC 6 バイト) + IPv4 (4 バイト) のみを受け入れ、
//! それ以外は破棄する。固定オフセットでパースできるのはこの前提があるから。

const std = @import("std");
const hexdump = @import("hexdump.zig");
const ethernet = @import("ethernet.zig");

pub const packet_len = 28;

pub const Ip4 = [4]u8;

pub const Oper = enum(u16) {
    request = 1,
    reply = 2,
    _,
};

pub const Packet = struct {
    oper: Oper,
    sender_mac: ethernet.Mac,
    sender_ip: Ip4,
    target_mac: ethernet.Mac,
    target_ip: Ip4,
};

pub const ParseError = error{
    PacketTooShort,
    UnsupportedHardware,
    UnsupportedProtocol,
};

/// ARP 本体（Ethernet ペイロード）をパースする。
/// 28 バイトを超える分は無視する（実 NIC 経由では最小フレーム長への
/// パディングが付いてくることがある）。
pub fn parse(bytes: []const u8) ParseError!Packet {
    if (bytes.len < packet_len) return error.PacketTooShort;
    // Ethernet + IPv4 以外はレイアウトが変わるため、固定オフセットで読む前に弾く
    if (hexdump.readU16(bytes[0..2]) != 1 or bytes[4] != 6) return error.UnsupportedHardware;
    // プロトコル種別は EtherType と同じ値空間を使う
    if (hexdump.readU16(bytes[2..4]) != @intFromEnum(ethernet.EtherType.ipv4) or bytes[5] != 4)
        return error.UnsupportedProtocol;

    return .{
        .oper = @enumFromInt(hexdump.readU16(bytes[6..8])),
        .sender_mac = bytes[8..14].*,
        .sender_ip = bytes[14..18].*,
        .target_mac = bytes[18..24].*,
        .target_ip = bytes[24..28].*,
    };
}

pub fn formatIp(writer: *std.Io.Writer, ip: Ip4) std.Io.Writer.Error!void {
    try writer.print("{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
}

// Step 3 で tcpdump から採取した ARP 要求の本体（Ethernet ヘッダを除いた 28 バイト）
const sample_request = [_]u8{
    0x00, 0x01, // ハードウェア種別: Ethernet
    0x08, 0x00, // プロトコル種別: IPv4
    0x06, // ハードウェアアドレス長
    0x04, // プロトコルアドレス長
    0x00, 0x01, // オペレーション: Request
    0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c, // 送信元 MAC
    0xc0, 0xa8, 0x46, 0x01, // 送信元 IP: 192.168.70.1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 宛先 MAC: 問い合わせ中なので 0
    0xc0, 0xa8, 0x46, 0x02, // 宛先 IP: 192.168.70.2 (このスタック)
};

test "ARP 要求をパースする" {
    const packet = try parse(&sample_request);

    try std.testing.expectEqual(Oper.request, packet.oper);
    try std.testing.expectEqual(ethernet.Mac{ 0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c }, packet.sender_mac);
    try std.testing.expectEqual(Ip4{ 192, 168, 70, 1 }, packet.sender_ip);
    try std.testing.expectEqual(ethernet.Mac{ 0, 0, 0, 0, 0, 0 }, packet.target_mac);
    try std.testing.expectEqual(Ip4{ 192, 168, 70, 2 }, packet.target_ip);
}

test "末尾のパディングは無視する" {
    const padded = sample_request ++ [_]u8{0} ** 18; // 46 バイト（最小ペイロード長）
    const packet = try parse(&padded);
    try std.testing.expectEqual(Oper.request, packet.oper);
}

test "28 バイトに満たない入力はエラー" {
    try std.testing.expectError(error.PacketTooShort, parse(&.{}));
    try std.testing.expectError(error.PacketTooShort, parse(sample_request[0..27]));
}

test "Ethernet + IPv4 以外は弾く" {
    var bytes = sample_request;
    bytes[1] = 6; // ハードウェア種別: IEEE 802
    try std.testing.expectError(error.UnsupportedHardware, parse(&bytes));

    bytes = sample_request;
    bytes[5] = 16; // プロトコルアドレス長: IPv6 相当
    try std.testing.expectError(error.UnsupportedProtocol, parse(&bytes));
}

test "未知のオペレーションも値を保持する" {
    var bytes = sample_request;
    bytes[7] = 9; // RARP 域の値
    const packet = try parse(&bytes);
    try std.testing.expectEqual(@as(u16, 9), @intFromEnum(packet.oper));
}

test "formatIp" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try formatIp(&w, .{ 192, 168, 70, 2 });
    try std.testing.expectEqualStrings("192.168.70.2", w.buffered());
}
