//! ARP — IPv4 アドレスから MAC アドレスを引く (RFC 826)。
//!
//! ARP 自体は汎用のアドレス解決プロトコルで、ハードウェア種別・プロトコル種別・
//! アドレス長のフィールドで任意の L2/L3 の組み合わせを表現できる。
//! このスタックでは Ethernet (MAC 6 バイト) + IPv4 (4 バイト) のみを受け入れ、
//! それ以外は破棄する。固定オフセットでパースできるのはこの前提があるから。
//!
//!   bytes 0-1   hrd  ハードウェア種別 (1 = Ethernet)
//!   bytes 2-3   pro  プロトコル種別 (0x0800 = IPv4)
//!   byte  4     hln  ハードウェアアドレス長 (6)
//!   byte  5     pln  プロトコルアドレス長 (4)
//!   bytes 6-7   op   オペレーション (1 = Request, 2 = Reply)
//!   bytes 8-13  sha  送信元 MAC (6)
//!   bytes 14-17 spa  送信元 IP (4)
//!   bytes 18-23 tha  宛先 MAC (6)
//!   bytes 24-27 tpa  宛先 IP (4)

const std = @import("std");
const hexdump = @import("hexdump.zig");
const ethernet = @import("ethernet.zig");

/// 合計サイズは本来可変長 (8 + hlen*2 + plen*2)。Ethernet + IPv4 なら
/// 8 + 6*2 + 4*2 = 28 バイトに固定される。
pub const packet_len = 28;
pub const Ip4 = [4]u8;

/// このスタック自身の IP アドレス。
/// カーネルはこの IP の存在を知らない — ARP 応答を返して初めて認識される。
/// 本来IPはインターフェース（NIC, TAP, Loなど）に付与される
pub const our_ip: Ip4 = .{ 192, 168, 70, 2 };

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
    if (hexdump.readU16(bytes[2..4]) != @intFromEnum(ethernet.EtherType.ip4) or bytes[5] != 4)
        return error.UnsupportedProtocol;

    return .{
        .oper = @enumFromInt(hexdump.readU16(bytes[6..8])),
        .sender_mac = bytes[8..14].*,
        .sender_ip = bytes[14..18].*,
        .target_mac = bytes[18..24].*,
        .target_ip = bytes[24..28].*,
    };
}

pub const BuildError = error{BufferTooSmall};

/// ARP 本体をバイト列に組み立てる（parse の逆）
/// hrd/pro/hln/pln は Ethernet + IPv4 の固定値を書く
pub fn build(buf: []u8, packet: Packet) BuildError![]u8 {
    if (buf.len < packet_len) return error.BufferTooSmall;

    hexdump.writeU16(buf[0..2], 1); // ハードウェア種別: 1 = Ethernet
    hexdump.writeU16(buf[2..4], @intFromEnum(ethernet.EtherType.ip4)); // プロトコル種別
    buf[4] = 6; // ハードウェアアドレス長
    buf[5] = 4; // プロトコルアドレス長
    hexdump.writeU16(buf[6..8], @intFromEnum(packet.oper)); // オペレーション (1 = Request, 2 = Reply)
    @memcpy(buf[8..14], &packet.sender_mac); // 送信元 MAC
    @memcpy(buf[14..18], &packet.sender_ip); // 送信元 IP
    @memcpy(buf[18..24], &packet.target_mac); // 宛先 MAC
    @memcpy(buf[24..28], &packet.target_ip); // 宛先 IP

    return buf[0..packet_len];
}

/// 自分宛の要求に対する応答を作る。
/// 送信元には自分を名乗り、宛先には要求の送信元をそのまま写す。
/// 要求では 0 埋めだった target_mac が、応答では「尋ねた本人」で埋まる。
pub fn replyTo(request: Packet) Packet {
    return .{
        .oper = .reply,
        .sender_mac = ethernet.our_mac,
        .sender_ip = our_ip,
        .target_mac = request.sender_mac,
        .target_ip = request.sender_ip,
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

test "parse と build で元のバイト列に戻る" {
    var buf: [packet_len]u8 = undefined;
    const bytes = try build(&buf, try parse(&sample_request));
    try std.testing.expectEqualSlices(u8, &sample_request, bytes);
}

test "バッファが足りなければエラー" {
    var buf: [packet_len - 1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        build(&buf, try parse(&sample_request)),
    );
}

test "要求から応答を作る" {
    const request = try parse(&sample_request);
    const reply = replyTo(request);

    try std.testing.expectEqual(Oper.reply, reply.oper);
    // 送信元は自分
    try std.testing.expectEqual(ethernet.our_mac, reply.sender_mac);
    try std.testing.expectEqual(our_ip, reply.sender_ip);
    // 宛先は尋ねてきた本人
    try std.testing.expectEqual(request.sender_mac, reply.target_mac);
    try std.testing.expectEqual(request.sender_ip, reply.target_ip);
}

test "formatIp" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try formatIp(&w, .{ 192, 168, 70, 2 });
    try std.testing.expectEqualStrings("192.168.70.2", w.buffered());
}
