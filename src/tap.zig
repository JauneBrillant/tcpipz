//! TAP デバイスの open / read / write（Linux 専用）。
//!
//! /dev/net/tun を open した時点では fd はまだ何者でもない。
//! TUNSETIFF ioctl で名前とモード（TAP = L2）を指定して初めて、
//! その fd が特定の仮想インターフェースに紐付く。
//!
//! 紐付いた後は、read すると「カーネルがそのインターフェースへ送信した
//! Ethernet フレーム」が 1 フレームずつ取れ、write すると「そのインター
//! フェースが受信したフレーム」としてカーネルに注入される。

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;

/// TUNSETIFF ioctl 番号: _IOW('T', 202, int) = 0x400454ca
const TUNSETIFF = linux.IOCTL.IOW('T', 202, c_int);

/// L2（Ethernet フレーム単位）モード。TUN (L3) は 0x0001
const IFF_TAP: c_short = 0x0002;
/// 各フレーム先頭に 4 バイトのパケット情報ヘッダを付けない
const IFF_NO_PI: c_short = 0x1000;

/// TUNSETIFF に渡す構造体（カーネルの struct ifreq、40 バイト）。
/// std.os.linux.ifreq にも同じものがあるが、flags フィールドが
/// インターフェース状態フラグ (IFF_UP など) 用の packed struct に
/// なっていて、TUN ドライバ独自のフラグ (IFF_TAP など) を表現できない。
/// そのためここでは生の c_short を持つ形で自前定義する。
const IfReq = extern struct {
    name: [linux.IFNAMESIZE]u8 = @splat(0),
    flags: c_short = 0,
    _pad: [40 - linux.IFNAMESIZE - @sizeOf(c_short)]u8 = @splat(0),
};

pub const Tap = struct {
    file: Io.File,

    /// /dev/net/tun を開き、name（例 "tap0"）の TAP デバイスに紐付ける。
    /// 対象デバイスが未作成なら新規作成される（要 CAP_NET_ADMIN）。
    pub fn open(io: Io, name: []const u8) !Tap {
        if (name.len >= linux.IFNAMESIZE) return error.NameTooLong;

        const file = try Io.Dir.openFileAbsolute(io, "/dev/net/tun", .{ .mode = .read_write });
        errdefer file.close(io);

        var req: IfReq = .{ .flags = IFF_TAP | IFF_NO_PI };
        @memcpy(req.name[0..name.len], name);

        // ioctl は Io インターフェースに無いので、生の fd に対して直接呼ぶ
        const rc = linux.ioctl(file.handle, TUNSETIFF, @intFromPtr(&req));
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            // NET_ADMIN ケーパビリティが無い
            .PERM => return error.AccessDenied,
            // 別プロセスが既に同名デバイスを掴んでいる
            .BUSY => return error.DeviceBusy,
            else => |e| return posix.unexpectedErrno(e),
        }

        return .{ .file = file };
    }

    pub fn close(self: *Tap, io: Io) void {
        self.file.close(io);
        self.* = undefined;
    }

    /// Ethernet フレームを 1 つ読む（ブロッキング）。
    /// TAP の read は必ず「1 回の read = 1 フレーム」になる。
    pub fn read(self: Tap, io: Io, buf: []u8) ![]u8 {
        const n = try self.file.readStreaming(io, &.{buf});
        return buf[0..n];
    }

    /// Ethernet フレームを 1 つ書き込む。
    pub fn write(self: Tap, io: Io, frame: []const u8) !void {
        try self.file.writeStreamingAll(io, frame);
    }
};
