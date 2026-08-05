//! TAP デバイス — カーネルのネットワークスタックとの出入口。
//!
//! TAP は Linux が提供する仮想 NIC で、片側がカーネル、もう片側が
//! このプロセスに繋がっている。カーネルから見ると本物の NIC と区別が
//! つかないため、対向で ping や nc といった標準ツールがそのまま動く。

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;

/// fd を「このインターフェースだ」とカーネルに登録するための ioctl 操作番号。
/// read/write は「バイトを運ぶ」ことしか表現できないため、こうした設定変更は
/// ioctl 経由になる。'T' は TUN/TAP サブシステムの識別子、202 はその中の通し番号。
///
/// 型を c_int にしているのはカーネルヘッダの定義 _IOW('T', 202, int) に合わせた
/// もの。実際に渡すのは 40 バイトの IfReq なので食い違って見えるが、番号
/// (0x400454ca) が一致しないとカーネルが認識しないため、ここは int のままにする。
const TUNSETIFF = linux.IOCTL.IOW('T', 202, c_int);

/// L2（Ethernet フレーム単位）モード。TUN (L3) は 0x0001
const IFF_TAP: c_short = 0x0002;
/// 各フレーム先頭に 4 バイトのパケット情報ヘッダを付けない
const IFF_NO_PI: c_short = 0x1000;

/// TUNSETIFF に渡す構造体（カーネルの struct ifreq、40 バイト）。
///
/// std.os.linux.ifreq でも表現できる（サイズも flags の位置も同じ）が、
/// あちらの flags は「インターフェース状態フラグ」用の packed struct で、
/// TUN のフラグとはビットの意味が違う。IFF_TAP は IFF_BROADCAST と同じ位置に
/// 来てしまい `.{ .BROADCAST = true }` と書く羽目になるため、意図がそのまま
/// 読めるよう flags: c_short を自前定義する。
const IfReq = extern struct {
    name: [linux.IFNAMESIZE]u8 = @splat(0),
    flags: c_short = 0,
    _pad: [40 - linux.IFNAMESIZE - @sizeOf(c_short)]u8 = @splat(0),
};

pub const Tap = struct {
    file: Io.File,

    /// `name` の TAP デバイスを開く。未作成なら新規作成する（要 CAP_NET_ADMIN）。
    pub fn open(io: Io, name: []const u8) !Tap {
        if (name.len >= linux.IFNAMESIZE) return error.NameTooLong;

        // /dev/net/tun は TUN/TAP を使う全員が共通で開く入口。
        // そのため、この時点の fd はまだどのインターフェースにも属していない
        const file = try Io.Dir.openFileAbsolute(io, "/dev/net/tun", .{ .mode = .read_write });
        errdefer file.close(io);

        // ifreq構造体を作成
        // インターフェースに対する要求の詳細
        // TAPモード、No Packet Information を設定する
        var req: IfReq = .{ .flags = IFF_TAP | IFF_NO_PI };
        @memcpy(req.name[0..name.len], name);

        // fd をインターフェースに繋ぎ、同時にモードを設定する。
        // ここで初めてカーネルがネットワークデバイスとして認識する
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

    /// カーネルがこのインターフェースへ送信したフレームを 1 つ読む
    /// （ブロッキング）。TAP は必ず「1 回の read = 1 フレーム」になる。
    pub fn read(self: Tap, io: Io, buf: []u8) ![]u8 {
        const n = try self.file.readStreaming(io, &.{buf});
        return buf[0..n];
    }

    /// フレームを 1 つ書き込む。カーネルからは「このインターフェースが
    /// 受信したフレーム」として扱われる。
    pub fn write(self: Tap, io: Io, frame: []const u8) !void {
        try self.file.writeStreamingAll(io, frame);
    }
};
