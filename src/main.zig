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
        try stdout.print("TAP devices only work on Linux. Run inside the container:\n", .{});
        try stdout.print("  docker compose up -d && docker compose exec dev bash\n", .{});
        try stdout.flush();
        return;
    }

    const tap = try tcpipz.Tap.open(io, "tap0");
    defer tap.close(io);

    try stdout.print("Opened tap0.\n", .{});

    try sendTestFrame(io, tap);
    try stdout.print("Sent test frame.\n", .{});

    try stdout.print("Waiting for frames...\n", .{});
    try stdout.flush();

    // MTU 1500 + Ethernet ヘッダ 14 に十分な受信バッファ
    var buf: [2048]u8 = undefined;
    while (true) {
        const bytes = try tap.read(io, &buf); // ブロッキング呼び出し
        try handleFrame(io, tap, stdout, bytes);
        try stdout.flush();
    }
}

/// Step 5 の動作確認用。まだ意味のあるプロトコルを 1 つも実装していないので、
/// 中身は「送れたことが分かる」だけのフレームを 1 つ流す。
///
/// フレーム長は 14 + 17 = 31 バイトで、最小フレーム長 60（FCS 除く）に満たない。
/// 最小長は物理層（CSMA/CD の衝突検出）の要請なので、物理層を持たない TAP では
/// パディング無しのまま通る。実 NIC なら送信時に NIC が 60 バイトまで埋める。
fn sendTestFrame(io: Io, tap: tcpipz.Tap) !void {
    const ethernet = tcpipz.ethernet;

    var buf: [64]u8 = undefined;
    const frame = try ethernet.build(&buf, .{
        .dst = ethernet.broadcast,
        .src = ethernet.our_mac,
        .ethertype = @enumFromInt(0x88b5), // IEEEがローカル実験用に予約している値
        .payload = "hello from tcpipz",
    });
    try tap.write(io, frame);
}

/// 受信したフレームを 1 つ処理する。
/// 上位層への振り分けは EtherType で行う。この形は以降の層でも繰り返される。
fn handleFrame(io: Io, tap: tcpipz.Tap, stdout: *Io.Writer, bytes: []const u8) !void {
    const ethernet = tcpipz.ethernet;

    const frame = ethernet.parse(bytes) catch |err| {
        try stdout.print("\n--- {d} bytes: dropped ({s}) ---\n", .{ bytes.len, @errorName(err) });
        return;
    };

    switch (frame.ethertype) {
        .arp => {
            try stdout.print("frame recieved : ethertype = arp\n", .{});
            try handleArp(io, tap, stdout, frame.payload);
            return;
        },
        .ip4 => {
            try stdout.print("frame recieved : ethertype = ipv4\n", .{});
            return;
        },
        .ip6 => return,
        else => return,
    }
}

/// 受信した ARP を tcpdump 風に表示し、自分の IP 宛の要求には応答を返す。
fn handleArp(io: Io, tap: tcpipz.Tap, stdout: *Io.Writer, payload: []const u8) !void {
    const arp = tcpipz.arp;
    const ethernet = tcpipz.ethernet;

    const packet = arp.parse(payload) catch |err| {
        try stdout.print("dropped ({s})\n", .{@errorName(err)});
        return;
    };

    // 自分宛の要求だけに応答する。他ホスト宛への要求も（ブロードキャストなので）
    // 届くが、所有していない IP に答えてはいけない
    if (packet.oper != .request) return;
    if (!std.mem.eql(u8, &packet.target_ip, &arp.our_ip)) return;

    // 応答はブロードキャストではなく、尋ねてきた本人へユニキャストで返す
    var arp_buf: [arp.packet_len]u8 = undefined;
    var frame_buf: [ethernet.header_len + arp.packet_len]u8 = undefined;
    const frame = try ethernet.build(&frame_buf, .{
        .dst = packet.sender_mac,
        .src = ethernet.our_mac,
        .ethertype = .arp,
        .payload = try arp.build(&arp_buf, arp.replyTo(packet)),
    });
    try tap.write(io, frame);

    try stdout.print("replied: ", .{});
    try arp.formatIp(stdout, arp.our_ip);
    try stdout.print(" is at ", .{});
    try ethernet.formatMac(stdout, ethernet.our_mac);
    try stdout.print("\n", .{});
}
