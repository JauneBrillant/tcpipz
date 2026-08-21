//! ポート多重化テーブル（ソケット）
//!
//! IP は「どのホストへ」までしか決められない。ホストの中で
//! 「どのプログラムへ」を決めるのがポート番号で、その対応表がここ
//!
//! OS の `socket()` / `bind()` が作っているのは、突き詰めればこの表の 1 行でしかない。
//! `bind(fd, port)` は「このポート宛が来たら自分に渡せ」とカーネルの表に登録する操作で、
//! `recvfrom()` はその行に溜まったデータを取り出す操作
//!
//! いまは UDP 専用。UDP は宛先ポートだけで宛先を決められるが、TCP は
//! **4 タプル**（送信元 IP・送信元ポート・宛先 IP・宛先ポート）で識別する。
//! 同じポート 80 に 1000 本の接続が同時に張れるのは、それぞれが別の 4 タプルだから

const std = @import("std");

pub const Handler = *const fn (payload: []const u8) ?[]const u8;
pub const BindError = error{ TableFull, PortInUse };

pub const Table = struct {
    pub const capacity = 8;
    const Entry = struct {
        port: u16,
        handler: Handler,
    };

    entries: [capacity]Entry = undefined,
    len: usize = 0,

    /// ポートにハンドラを結びつける。`bind(2)` にあたる
    pub fn bind(self: *Table, port: u16, handler: Handler) BindError!void {
        if (self.lookup(port) != null) return error.PortInUse;
        if (self.len == capacity) return error.TableFull;
        self.entries[self.len] = .{ .port = port, .handler = handler };
        self.len += 1;
    }

    /// ポートに対応するハンドラを返す
    pub fn lookup(self: *const Table, port: u16) ?Handler {
        for (self.entries[0..self.len]) |entry| {
            if (entry.port == port) return entry.handler;
        }
        return null;
    }
};

/// echo (RFC 862): 受け取ったものをそのまま返す
pub fn echo(payload: []const u8) ?[]const u8 {
    return payload;
}

/// discard (RFC 863): 受け取って捨てる。応答しない
pub fn discard(_: []const u8) ?[]const u8 {
    return null;
}

test "登録したポートだけが引ける" {
    var table: Table = .{};
    try table.bind(7, echo);
    try table.bind(9, discard);

    try std.testing.expect(table.lookup(7) != null);
    try std.testing.expect(table.lookup(9) != null);
    try std.testing.expectEqual(null, table.lookup(8));
}

test "ポートごとに別のハンドラへ振り分けられる" {
    var table: Table = .{};
    try table.bind(7, echo);
    try table.bind(9, discard);

    // 同じペイロードでも、宛先ポートが違えば結果が違う
    const payload = "hello";
    try std.testing.expectEqualStrings(payload, table.lookup(7).?(payload).?);
    try std.testing.expectEqual(null, table.lookup(9).?(payload));
}

test "echo が返すのは入力スライスそのもの（コピーしない）" {
    const payload = "hello";
    try std.testing.expectEqual(payload.ptr, echo(payload).?.ptr);
}

test "同じポートの二重登録はエラー" {
    var table: Table = .{};
    try table.bind(7, echo);
    try std.testing.expectError(error.PortInUse, table.bind(7, discard));
    try std.testing.expectEqual(@as(usize, 1), table.len);
}

test "満杯になったらエラー" {
    var table: Table = .{};
    for (0..Table.capacity) |i| try table.bind(@intCast(1000 + i), discard);
    try std.testing.expectError(error.TableFull, table.bind(2000, echo));
}
