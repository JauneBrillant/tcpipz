//! TAP デバイス — カーネルのネットワークスタックとの出入口。
//! カーネルから見ると本物の NIC と同じなので、対向で ping や tcpdump がそのまま動く。

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;

file: Io.File,

const Tap = @This();

// TUN/TAP の ioctl 番号とフラグ。std には無いのでカーネルヘッダ (linux/if_tun.h) から写す。
// c_int は _IOW('T', 202, int) に合わせるためで、実際に渡すのは IfReq（番号さえ合えばよい）。
const TUNSETIFF = linux.IOCTL.IOW('T', 202, c_int);
const IFF_TAP: c_short = 0x0002; // L2 (Ethernet フレーム単位)。TUN (L3) は 0x0001
const IFF_NO_PI: c_short = 0x1000; // フレーム先頭に 4 バイトの情報ヘッダを付けない

/// カーネルの struct ifreq (40 バイト)。std.os.linux.ifreq の flags は
/// インターフェース状態フラグ用の packed struct で TUN のフラグとビットの意味が
/// 合わないため、必要な形だけ自前定義する。
const IfReq = extern struct {
    name: [linux.IFNAMESIZE]u8 = @splat(0),
    flags: c_short,
    _pad: [40 - linux.IFNAMESIZE - @sizeOf(c_short)]u8 = @splat(0),
};

/// `name` の TAP デバイスを開く。未作成なら新規作成される（要 CAP_NET_ADMIN）。
pub fn open(io: Io, name: []const u8) !Tap {
    if (name.len >= linux.IFNAMESIZE) return error.NameTooLong;

    // /dev/net/tun は TUN/TAP 共通の入口。どのインターフェースに属すかは次の ioctl で決まる
    const file = try Io.Dir.openFileAbsolute(io, "/dev/net/tun", .{ .mode = .read_write });
    errdefer file.close(io);

    var req: IfReq = .{ .flags = IFF_TAP | IFF_NO_PI };
    @memcpy(req.name[0..name.len], name);
    switch (posix.errno(linux.ioctl(file.handle, TUNSETIFF, @intFromPtr(&req)))) {
        .SUCCESS => {},
        .PERM => return error.AccessDenied, // NET_ADMIN ケーパビリティが無い
        .BUSY => return error.DeviceBusy, // 別プロセスが同名デバイスを掴んでいる
        else => |e| return posix.unexpectedErrno(e),
    }

    return .{ .file = file };
}

pub fn close(self: Tap, io: Io) void {
    self.file.close(io);
}

/// フレームを 1 つ読む（ブロッキング）。TAP は必ず「1 回の read = 1 フレーム」。
pub fn read(self: Tap, io: Io, buf: []u8) ![]u8 {
    return buf[0..try self.file.readStreaming(io, &.{buf})];
}

/// フレームを 1 つ書く。カーネルからは「この NIC が受信したフレーム」として扱われる。
pub fn write(self: Tap, io: Io, frame: []const u8) !void {
    try self.file.writeStreamingAll(io, frame);
}
