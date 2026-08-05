//! Ethernet II フレームの解析。
//!
//! フレームの先頭 14 バイトがヘッダで、その後ろがペイロード。
//!
//!   | 宛先 MAC 6 | 送信元 MAC 6 | EtherType 2 | ペイロード ... |
//!
//! EtherType が「ペイロードをどの上位層に渡すか」を決める。この
//! 「1 つのフィールドで上位層を振り分ける」構造は、IPv4 のプロトコル番号
//! (1=ICMP, 6=TCP, 17=UDP) でも同じ形で繰り返し現れる。

const std = @import("std");
const hexdump = @import("hexdump.zig");

/// ヘッダの長さ。TAP から読めるフレームには FCS（末尾の CRC）は含まれない。
pub const header_len = 14;

pub const Mac = [6]u8;

/// 全員宛。ARP 要求のように「このセグメントの誰か」に呼びかけるときに使う。
pub const broadcast: Mac = @splat(0xff);

/// ペイロードをどの上位層で解釈するかを示す。
/// 1500 以下の値は Ethernet II ではなく古い IEEE 802.3 の「長さ」を意味するが、
/// 現代のネットワークではまず現れないのでここでは扱わない。
pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86dd,
    _,
};

pub const Frame = struct {
    dst: Mac,
    src: Mac,
    ethertype: EtherType,
    /// 入力スライスの中を指す。コピーはしない。
    payload: []const u8,
};

pub const ParseError = error{FrameTooShort};

/// フレームをヘッダとペイロードに分解する。純粋関数で、I/O も確保も行わない。
pub fn parse(bytes: []const u8) ParseError!Frame {
    if (bytes.len < header_len) return error.FrameTooShort;
    return .{
        .dst = bytes[0..6].*,
        .src = bytes[6..12].*,
        .ethertype = @enumFromInt(hexdump.readU16(bytes[12..14])),
        .payload = bytes[header_len..],
    };
}

/// MAC アドレスを 02:00:00:00:00:02 の形式で書き出す。
pub fn formatMac(writer: *std.Io.Writer, mac: Mac) std.Io.Writer.Error!void {
    for (mac, 0..) |b, i| {
        if (i != 0) try writer.writeByte(':');
        try writer.print("{x:0>2}", .{b});
    }
}

/// Step 3 でコンテナ内の tcpdump から採取した実物の ARP 要求（42 バイト）。
/// カーネル (192.168.70.1) が 192.168.70.2 の MAC を尋ねている。
const sample_arp_request = [_]u8{
    // Ethernet ヘッダ
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 宛先: ブロードキャスト
    0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c, // 送信元: カーネル側の MAC
    0x08, 0x06, // EtherType: ARP
    // ペイロード（ARP 本体 28 バイト。中身は Step 6 で扱う）
    0x00, 0x01,
    0x08, 0x00,
    0x06, 0x04,
    0x00, 0x01,
    0xde, 0xda,
    0x6c, 0x00,
    0x2b, 0x9c,
    0xc0, 0xa8,
    0x46, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0xc0, 0xa8,
    0x46, 0x02,
};

test "実物の ARP 要求をパースする" {
    const frame = try parse(&sample_arp_request);

    try std.testing.expectEqual(broadcast, frame.dst);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c }, &frame.src);
    try std.testing.expectEqual(EtherType.arp, frame.ethertype);

    // ペイロードは ARP 本体の 28 バイト
    try std.testing.expectEqual(@as(usize, 28), frame.payload.len);
    // ARP の先頭 2 バイトはハードウェア種別 = 1 (Ethernet)
    try std.testing.expectEqual(@as(u16, 1), hexdump.readU16(frame.payload[0..2]));
}

test "ペイロードは入力スライスへの参照（コピーしない）" {
    const frame = try parse(&sample_arp_request);
    try std.testing.expectEqual(
        @intFromPtr(&sample_arp_request[header_len]),
        @intFromPtr(frame.payload.ptr),
    );
}

test "ヘッダに満たない入力はエラー" {
    try std.testing.expectError(error.FrameTooShort, parse(&.{}));
    try std.testing.expectError(error.FrameTooShort, parse(sample_arp_request[0..13]));
    // ちょうど 14 バイトなら、ペイロードが空でも成功する
    const frame = try parse(sample_arp_request[0..14]);
    try std.testing.expectEqual(@as(usize, 0), frame.payload.len);
}

test "未知の EtherType も値を保持できる" {
    var bytes = sample_arp_request;
    hexdump.writeU16(bytes[12..14], 0x1234);
    const frame = try parse(&bytes);
    try std.testing.expectEqual(@as(u16, 0x1234), @intFromEnum(frame.ethertype));
}

test "formatMac" {
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try formatMac(&w, .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 });
    try std.testing.expectEqualStrings("02:00:00:00:00:02", w.buffered());
}
