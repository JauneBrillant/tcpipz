const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const tcpipz = @import("tcpipz");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    // TAP は Linux 専用。ホスト (macOS) でうっかり実行したときに
    // 分かりやすく伝える。builtin.os.tag はコンパイル時に確定するので、
    // macOS ビルドでは以降の Linux 専用コードは解析すらされない。
    if (builtin.os.tag != .linux) {
        try stdout.print("TAP デバイスは Linux でのみ使える。コンテナ内で実行すること:\n", .{});
        try stdout.print("  docker compose up -d && docker compose exec dev bash\n", .{});
        try stdout.flush();
        return;
    }

    var tap = try tcpipz.tap.Tap.open(io, "tap0");
    defer tap.close(io);

    try stdout.print("tap0 を開いた。\n", .{});

    try sendTestFrame(io, tap);
    try stdout.print("テストフレームを送出した。\n", .{});

    try stdout.print("フレーム待機中...\n", .{});
    try stdout.flush();

    // MTU 1500 + Ethernet ヘッダ 14 に十分な受信バッファ
    var buf: [2048]u8 = undefined;
    while (true) {
        const bytes = try tap.read(io, &buf);
        try handleFrame(stdout, bytes);
        try stdout.flush();
    }
}

/// Step 5 の動作確認用。まだ意味のあるプロトコルを 1 つも実装していないので、
/// 中身は「送れたことが分かる」だけのフレームを 1 つ流す。
///
/// EtherType 0x88b5 は IEEE がローカル実験用に予約している値で、割り当てられた
/// プロトコルが無い。カーネルは受け取っても渡す先が無く黙って捨てるため、
/// 副作用を気にせず送出そのものだけを確認できる。tcpdump はプロトコル振り分けの
/// 手前で生フレームを複製するので、捨てられるフレームでも観測はできる。
///
/// フレーム長は 14 + 17 = 31 バイトで、最小フレーム長 60（FCS 除く）に満たない。
/// 最小長は物理層（CSMA/CD の衝突検出）の要請なので、物理層を持たない TAP では
/// パディング無しのまま通る。実 NIC なら送信時に NIC が 60 バイトまで埋める。
fn sendTestFrame(io: Io, tap: tcpipz.tap.Tap) !void {
    const ethernet = tcpipz.ethernet;

    var buf: [64]u8 = undefined;
    const frame = try ethernet.build(&buf, .{
        .dst = ethernet.broadcast,
        .src = ethernet.our_mac,
        .ethertype = @enumFromInt(0x88b5),
        .payload = "hello from tcpipz",
    });
    try tap.write(io, frame);
}

/// 受信したフレームを 1 つ処理する。
/// 上位層への振り分けは EtherType で行う。この形は以降の層でも繰り返される。
fn handleFrame(stdout: *Io.Writer, bytes: []const u8) !void {
    const ethernet = tcpipz.ethernet;

    const frame = ethernet.parse(bytes) catch |err| {
        try stdout.print("\n--- {d} bytes: 破棄 ({s}) ---\n", .{ bytes.len, @errorName(err) });
        return;
    };

    try stdout.print("\n--- {d} bytes  ", .{bytes.len});
    try ethernet.formatMac(stdout, frame.src);
    try stdout.print(" -> ", .{});
    try ethernet.formatMac(stdout, frame.dst);
    try stdout.print("  ", .{});

    switch (frame.ethertype) {
        .arp => try stdout.print("ARP ---\n", .{}),
        .ipv4 => try stdout.print("IPv4 ---\n", .{}),
        // カーネルは新しいインターフェースが上がると勝手に IPv6 の近隣探索を
        // 始める。このスタックでは扱わないので、種別だけ出して中身は見ない。
        .ipv6 => {
            // try stdout.print("IPv6 ---\n", .{});
            return;
        },
        else => |t| try stdout.print("EtherType 0x{x:0>4} ---\n", .{@intFromEnum(t)}),
    }

    // 今はまだどの層も実装していないので、ペイロードを dump するだけ
    try tcpipz.hexdump.dump(stdout, frame.payload);
}
