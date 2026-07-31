//! 16 進ダンプとネットワークバイトオーダー変換のヘルパ。
//!
//! ネットワークプロトコルのヘッダはすべてビッグエンディアン（ネットワーク
//! バイトオーダー）で並んでいる。x86 / ARM はリトルエンディアンなので、
//! マルチバイトのフィールドを読み書きするときは必ずここの関数を通す。

const std = @import("std");
const Io = std.Io;

/// バイト列の先頭 2 バイトをビッグエンディアンの u16 として読む。
pub fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

/// バイト列の先頭 4 バイトをビッグエンディアンの u32 として読む。
pub fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

/// u16 をビッグエンディアンでバッファ先頭 2 バイトに書く。
pub fn writeU16(buf: []u8, value: u16) void {
    std.mem.writeInt(u16, buf[0..2], value, .big);
}

/// u32 をビッグエンディアンでバッファ先頭 4 バイトに書く。
pub fn writeU32(buf: []u8, value: u32) void {
    std.mem.writeInt(u32, buf[0..4], value, .big);
}

/// バイト列を `tcpdump -x` 風に 16 進ダンプする。
///
/// 1 行 16 バイト、2 バイトごとに区切る:
///     0x0000:  ffff ffff ffff 0800 2700 0001 0806 0001
///     0x0010:  0800 0604 0001 ...
pub fn dump(writer: *Io.Writer, bytes: []const u8) Io.Writer.Error!void {
    var offset: usize = 0;
    while (offset < bytes.len) : (offset += 16) {
        const line = bytes[offset..@min(offset + 16, bytes.len)];
        try writer.print("0x{x:0>4}: ", .{offset});
        for (line, 0..) |b, i| {
            if (i % 2 == 0) try writer.writeByte(' ');
            try writer.print("{x:0>2}", .{b});
        }
        try writer.writeByte('\n');
    }
}

test "readU16: ネットワークバイトオーダーで読む" {
    // 0x08, 0x00 の並びは EtherType の IPv4 (0x0800)。
    // リトルエンディアンで読むと 0x0008 になってしまう。
    try std.testing.expectEqual(@as(u16, 0x0800), readU16(&.{ 0x08, 0x00 }));
    try std.testing.expectEqual(@as(u16, 0x0806), readU16(&.{ 0x08, 0x06 }));
}

test "readU32: ネットワークバイトオーダーで読む" {
    // 192.168.70.1 を u32 で見ると 0xc0a84601
    try std.testing.expectEqual(@as(u32, 0xc0a84601), readU32(&.{ 0xc0, 0xa8, 0x46, 0x01 }));
}

test "writeU16 / writeU32: 書いたものを読み戻せる" {
    var buf: [4]u8 = undefined;

    writeU16(&buf, 0x0800);
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x00 }, buf[0..2]);
    try std.testing.expectEqual(@as(u16, 0x0800), readU16(&buf));

    writeU32(&buf, 0xc0a84601);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0xa8, 0x46, 0x01 }, &buf);
    try std.testing.expectEqual(@as(u32, 0xc0a84601), readU32(&buf));
}

test "dump: 16 バイトちょうどの 1 行" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);

    try dump(&w, &.{
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0xb1, 0xe6, 0xac, 0x10, 0x0a, 0x63,
    });
    try std.testing.expectEqualStrings(
        "0x0000:  4500 003c 1c46 4000 4006 b1e6 ac10 0a63\n",
        w.buffered(),
    );
}

test "dump: 複数行と半端な長さ" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);

    // 19 バイト = 16 バイトの行 + 3 バイトの行（奇数長の端数を含む）
    try dump(&w, &.{
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0xb1, 0xe6, 0xac, 0x10, 0x0a, 0x63,
        0x01, 0x02, 0x03,
    });
    try std.testing.expectEqualStrings(
        "0x0000:  4500 003c 1c46 4000 4006 b1e6 ac10 0a63\n" ++
            "0x0010:  0102 03\n",
        w.buffered(),
    );
}

test "dump: 空入力は何も出力しない" {
    var buf: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try dump(&w, &.{});
    try std.testing.expectEqualStrings("", w.buffered());
}
