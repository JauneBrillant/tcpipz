//! ARP — IPv4 アドレスから MAC アドレスを引く (RFC 826)。
//!
//! Ethernet フレームのペイロードとして運ばれる (EtherType = 0x0806)。
//! 28 バイトでは最小ペイロード長 46 に足りないので、末尾に詰め物が付く:
//!
//!    --- Ethernet Frame with Arp packet ---
//!   ┌─ Ethernet header 14 ─┬─ ARP packet 28 ─┬─ padding 18 ─┐
//!   └──────────────────────┴─────────────────┴──────────────┘
//!
//!    --- Arp Packet ---
//!   ┌───────┬───────┬─────┬─────┬───────┬───────┬───────┬───────┬───────┐
//!   │  hrd  │  pro  │ hln │ pln │  op   │  sha  │  spa  │  tha  │  tpa  │
//!   │   2   │   2   │  1  │  1  │   2   │   6   │   4   │   6   │   4   │
//!   └───────┴───────┴─────┴─────┴───────┴───────┴───────┴───────┴───────┘
//!   0       2       4     5     6       8       14      18      24      28
//!
//!   hrd  ハードウェア種別 (1 = Ethernet)
//!   pro  プロトコル種別 (0x0800 = IPv4)
//!   hln  ハードウェアアドレス長 (6)
//!   pln  プロトコルアドレス長 (4)
//!   op   オペレーション (1 = Request, 2 = Reply)
//!   sha  送信元 MAC
//!   spa  送信元 IP
//!   tha  宛先 MAC
//!   tpa  宛先 IP

const std = @import("std");
const hexdump = @import("hexdump.zig");
const ethernet = @import("ethernet.zig");

/// 合計サイズは本来可変長 (8 + hlen*2 + plen*2)。Ethernet + IPv4 なら
/// 8 + 6*2 + 4*2 = 28 バイトに固定される。
pub const packet_len = 28;

pub const Ip4 = @import("ip.zig").Addr;
pub const our_ip = @import("ip.zig").our_addr;

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

/// 生のバイト列で表現された Arp 要求(Ethernet ペイロード) を Packet 構造体に変換する
///
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

/// ARP 本体をバイト列に組み立てる
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

/// 自分宛のARP要求に対するARP応答パケットを作る。
pub fn replyTo(request: Packet) Packet {
    return .{
        .oper = .reply,
        .sender_mac = ethernet.our_mac,
        .sender_ip = our_ip,
        .target_mac = request.sender_mac,
        .target_ip = request.sender_ip,
    };
}

/// 指定した IP の持ち主に MAC を尋ねる ARP 要求の Packet を作る
pub fn requestFor(target_ip: Ip4) Packet {
    return .{
        .oper = .request,
        .sender_mac = ethernet.our_mac,
        .sender_ip = our_ip,
        .target_mac = @splat(0),
        .target_ip = target_ip,
    };
}

/// IP → MAC のキャッシュ (RFC 826 の "translation table")。
///
/// 線形探索で足りる。同一セグメントに何百台もいる状況を想定していないし、
/// 引くのは送信のたびに 1 回だけ。
///
/// 有効期限は持たない。実運用のスタックはエントリを数十秒〜数分で失効させる
/// （相手の NIC が交換される、IP が別のホストへ移る、といったことが起きるため）が、
/// 対向がカーネル 1 台しかいない TAP リンクではその状況が起きない。
/// 必要になるのは複数ホストのセグメントに出たとき。
pub const Table = struct {
    pub const capacity = 16;

    const Entry = struct {
        ip: Ip4,
        mac: ethernet.Mac,
    };

    entries: [capacity]Entry = undefined,
    /// 使用中のスロット数。entries[0..len] だけが有効。
    len: usize = 0,
    /// 満杯のとき次に上書きするスロット。挿入した順に追い出す。
    oldest: usize = 0,

    /// 未登録なら null。呼び出し側は ARP 要求を出すことになる。
    pub fn lookup(self: *const Table, ip: Ip4) ?ethernet.Mac {
        for (self.entries[0..self.len]) |entry| {
            if (std.mem.eql(u8, &entry.ip, &ip)) return entry.mac;
        }
        return null;
    }

    /// 登録済みの IP なら MAC を上書きする。相手の NIC が変わっても追従できる —
    /// 有効期限を持たない代わりに、相手が話しかけてくるたびに最新化される。
    pub fn put(self: *Table, ip: Ip4, mac: ethernet.Mac) void {
        for (self.entries[0..self.len]) |*entry| {
            if (std.mem.eql(u8, &entry.ip, &ip)) {
                entry.mac = mac;
                return;
            }
        }
        if (self.len < capacity) {
            self.entries[self.len] = .{ .ip = ip, .mac = mac };
            self.len += 1;
            return;
        }
        self.entries[self.oldest] = .{ .ip = ip, .mac = mac };
        self.oldest = (self.oldest + 1) % capacity;
    }
};

pub fn formatIp(writer: *std.Io.Writer, ip: Ip4) std.Io.Writer.Error!void {
    try writer.print("{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
}

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

test "尋ねる要求を作る" {
    const request = requestFor(.{ 192, 168, 70, 1 });

    try std.testing.expectEqual(Oper.request, request.oper);
    try std.testing.expectEqual(ethernet.our_mac, request.sender_mac);
    try std.testing.expectEqual(our_ip, request.sender_ip);
    // 尋ねている当の値なので 0 埋め
    try std.testing.expectEqual(@as(ethernet.Mac, @splat(0)), request.target_mac);
    try std.testing.expectEqual(Ip4{ 192, 168, 70, 1 }, request.target_ip);
}

const mac_a: ethernet.Mac = .{ 0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c };
const mac_b: ethernet.Mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x09 };

test "テーブル: 挿入して引く" {
    var table: Table = .{};
    try std.testing.expectEqual(null, table.lookup(.{ 192, 168, 70, 1 }));

    table.put(.{ 192, 168, 70, 1 }, mac_a);
    try std.testing.expectEqual(mac_a, table.lookup(.{ 192, 168, 70, 1 }));
    // 登録していない IP は引けない
    try std.testing.expectEqual(null, table.lookup(.{ 192, 168, 70, 3 }));
}

test "テーブル: 同じ IP は上書きし、エントリは増えない" {
    var table: Table = .{};
    table.put(.{ 192, 168, 70, 1 }, mac_a);
    table.put(.{ 192, 168, 70, 1 }, mac_b);

    try std.testing.expectEqual(mac_b, table.lookup(.{ 192, 168, 70, 1 }));
    try std.testing.expectEqual(@as(usize, 1), table.len);
}

test "テーブル: 満杯なら古い順に追い出す" {
    var table: Table = .{};
    for (0..Table.capacity) |i| {
        table.put(.{ 192, 168, 70, @intCast(i) }, mac_a);
    }
    try std.testing.expectEqual(Table.capacity, table.len);

    // 1 件あふれさせると、最初に入れたものが消える
    table.put(.{ 10, 0, 0, 1 }, mac_b);
    try std.testing.expectEqual(Table.capacity, table.len);
    try std.testing.expectEqual(null, table.lookup(.{ 192, 168, 70, 0 }));
    try std.testing.expectEqual(mac_b, table.lookup(.{ 10, 0, 0, 1 }));
    // 2 番目以降は残っている
    try std.testing.expectEqual(mac_a, table.lookup(.{ 192, 168, 70, 1 }));
}

test "テーブル: 受信した要求からも応答からも学習できる" {
    var table: Table = .{};
    const request = try parse(&sample_request);
    table.put(request.sender_ip, request.sender_mac);

    try std.testing.expectEqual(request.sender_mac, table.lookup(.{ 192, 168, 70, 1 }));
}

test "formatIp" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try formatIp(&w, .{ 192, 168, 70, 2 });
    try std.testing.expectEqualStrings("192.168.70.2", w.buffered());
}
