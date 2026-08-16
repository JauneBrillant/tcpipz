//! Ethernet II フレーム。
//!
//! プリアンブル(7) と SFD(1) は物理層が付ける同期用の前置き、FCS(4) は末尾の誤り検出符号
//! どちらも TAP からは見えない。TAP で読み書きするのは宛先 MAC 〜 ペイロードのみ、14 バイトのヘッダ:
//!
//!    ┌─ Ethernet フレーム ─────────────────────┐
//!    │ dst(6) src(6) EtherType(2) │ ペイロード │
//!    └────────────────────────────┴────────────┘
//!     EtherType でペイロードの中身が決まる
//!         ├─ 0x0806 → ARP  パケット (28 バイト)
//!         ├─ 0x0800 → IPv4 パケット (20 バイト〜)
//!         └─ 0x86dd → IPv6 パケット

const std = @import("std");
const hexdump = @import("hexdump.zig");

pub const header_len = 14;
pub const Mac = [6]u8;
pub const broadcast: Mac = @splat(0xff);
/// このスタック自身の MAC アドレス。
/// 先頭の `0x02` は bit0 (I/G) = 0: ユニキャスト、bit1 (U/L) = 1: ローカル管理。
/// ローカル管理を宣言しているので、勝手に決めた値でも実在の NIC と衝突しない。
pub const our_mac: Mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };

/// EtherType が「ペイロードをどの上位層に渡すか」を決める
pub const EtherType = enum(u16) {
    ip4 = 0x0800,
    arp = 0x0806,
    ip6 = 0x86dd,
    _,
};

pub const Frame = struct {
    dst: Mac,
    src: Mac,
    ethertype: EtherType,
    payload: []const u8,
};

pub const ParseError = error{FrameTooShort};

/// フレームをヘッダとペイロードに分解する
pub fn parse(bytes: []const u8) ParseError!Frame {
    if (bytes.len < header_len) return error.FrameTooShort;
    return .{
        .dst = bytes[0..6].*,
        .src = bytes[6..12].*,
        .ethertype = @enumFromInt(hexdump.readU16(bytes[12..14])),
        .payload = bytes[header_len..],
    };
}

pub const BuildError = error{BufferTooSmall};

/// フレームをバイト列に組み立てる（parse の逆）
pub fn build(buf: []u8, frame: Frame) BuildError![]u8 {
    const frame_len = header_len + frame.payload.len;
    if (buf.len < frame_len) return error.BufferTooSmall;

    @memcpy(buf[0..6], &frame.dst);
    @memcpy(buf[6..12], &frame.src);
    hexdump.writeU16(buf[12..14], @intFromEnum(frame.ethertype));
    @memcpy(buf[header_len..frame_len], frame.payload);

    return buf[0..frame_len];
}

pub fn formatMac(writer: *std.Io.Writer, mac: Mac) std.Io.Writer.Error!void {
    for (mac, 0..) |b, i| {
        if (i != 0) try writer.writeByte(':');
        try writer.print("{x:0>2}", .{b});
    }
}

const sample_arp_request = [_]u8{
    // Ethernet ヘッダ
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 宛先: ブロードキャスト
    0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c, // 送信元: カーネル側の MAC
    0x08, 0x06, // EtherType: ARP

    // ペイロード = ARP 本体 (RFC 826)
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
    const frame = try parse(&sample_arp_request);

    try std.testing.expectEqual(broadcast, frame.dst);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c },
        &frame.src,
    );
    try std.testing.expectEqual(EtherType.arp, frame.ethertype);

    // ペイロードは ARP 本体の 28 バイト
    try std.testing.expectEqual(@as(usize, 28), frame.payload.len);
    // ARP の先頭 2 バイトはハードウェア種別 = 1 (Ethernet)
    try std.testing.expectEqual(@as(u16, 1), hexdump.readU16(frame.payload[0..2]));
}

// 1500バイトのフレームが毎秒何万とくることが想定されるので
// パースの度にペイロードをコピーする変更を許さない
test "ペイロードは入力スライスへの参照" {
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

test "組み立てた結果は実物のバイト列と一致する" {
    var buf: [64]u8 = undefined;
    const bytes = try build(&buf, .{
        .dst = broadcast,
        .src = .{ 0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c },
        .ethertype = .arp,
        .payload = sample_arp_request[header_len..],
    });
    try std.testing.expectEqualSlices(u8, &sample_arp_request, bytes);
}

test "build した結果を parse で戻せる" {
    var buf: [64]u8 = undefined;
    const original: Frame = .{
        .dst = broadcast,
        .src = our_mac,
        .ethertype = .ip4,
        .payload = "hello",
    };
    const parsed = try parse(try build(&buf, original));
    // original ptr -> 実行ファイルの定数領域を指す
    // parsed   ptr -> スタック上のbufを指す
    // ので、expectEqualDeepでの比較をする
    try std.testing.expectEqualDeep(original, parsed);
}

test "バッファが足りなければエラー" {
    // ヘッダ 14 + ペイロード 5 = 19 バイト必要
    var buf: [18]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, build(&buf, .{
        .dst = broadcast,
        .src = our_mac,
        .ethertype = .ip4,
        .payload = "hello",
    }));
}

test "our_mac はローカル管理のユニキャストアドレス" {
    try std.testing.expectEqual(@as(u8, 0), our_mac[0] & 0b01); // I/G: ユニキャスト
    try std.testing.expectEqual(@as(u8, 0b10), our_mac[0] & 0b10); // U/L: ローカル管理
}

test "formatMac" {
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try formatMac(&w, .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 });
    try std.testing.expectEqualStrings("02:00:00:00:00:02", w.buffered());
}
