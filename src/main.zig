const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const tcpipz = @import("tcpipz");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    if (builtin.os.tag != .linux) {
        try stdout.print("TAP devices only work on Linux. Run inside the container:\n", .{});
        try stdout.print("  docker compose up -d && docker compose exec dev bash\n", .{});
        try stdout.flush();
        return;
    }

    const tap = try tcpipz.Tap.open(io, "tap0");
    defer tap.close(io);

    try stdout.print("Opened tap0.\n", .{});

    var table: tcpipz.arp.Table = .{};
    var tx_buf: [tcpipz.ethernet.max_frame_len]u8 = undefined;

    // 起動時に一度、まだ何も知らない状態で送信経路を叩いてみる。
    // テーブルが空なので .resolving が返り、ARP 要求だけが出る
    const probe, const probe_frame = try tcpipz.ip.send(&tx_buf, &table, kernel_ip, .icmp, "");
    try tap.write(io, probe_frame);
    try stdout.print("startup probe: {s}\n", .{@tagName(probe)});

    try stdout.print("Waiting for frames...\n", .{});
    try stdout.flush();

    var rx_buf: [2048]u8 = undefined;
    while (true) {
        const bytes = try tap.read(io, &rx_buf); // ブロッキング呼び出し
        if (try handleFrame(&tx_buf, stdout, &table, bytes)) |frame| try tap.write(io, frame);
        try stdout.flush();
    }
}

/// カーネル側 tap0 の IP。このスタックから見た唯一の通信相手。
const kernel_ip: tcpipz.arp.Ip4 = .{ 192, 168, 70, 1 };

/// 受信したフレームを 1 つ処理する。
fn handleFrame(
    out: []u8,
    stdout: *Io.Writer,
    table: *tcpipz.arp.Table,
    bytes: []const u8,
) !?[]const u8 {
    const ethernet = tcpipz.ethernet;

    const frame = ethernet.parse(bytes) catch |err| {
        try stdout.print("\n--- {d} bytes: dropped ({s}) ---\n", .{ bytes.len, @errorName(err) });
        return null;
    };

    // 上位層への振り分けをEtherTypeで行う
    switch (frame.ethertype) {
        .arp => {
            try stdout.print("frame received : ethertype = arp\n", .{});
            return try handleArp(out, stdout, table, frame.payload);
        },
        .ip4 => {
            try stdout.print("frame received : ethertype = ipv4\n", .{});
            return try handleIp4(out, stdout, table, frame.payload);
        },
        .ip6 => return null,
        else => return null,
    }
}

/// 振り分けられた Arp パケットを処理する
fn handleArp(
    out: []u8,
    stdout: *Io.Writer,
    table: *tcpipz.arp.Table,
    payload: []const u8,
) !?[]const u8 {
    const arp = tcpipz.arp;
    const ethernet = tcpipz.ethernet;

    const packet = arp.parse(payload) catch |err| {
        try stdout.print("dropped ({s})\n", .{@errorName(err)});
        return null;
    };

    table.put(packet.sender_ip, packet.sender_mac);

    if (packet.oper != .request) return null;
    if (!std.mem.eql(u8, &packet.target_ip, &arp.our_ip)) return null;

    var arp_buf: [arp.packet_len]u8 = undefined;
    const reply = try ethernet.build(out, .{
        .dst = packet.sender_mac,
        .src = ethernet.our_mac,
        .ethertype = .arp,
        .payload = try arp.build(&arp_buf, arp.replyTo(packet)),
    });

    return reply;
}

/// 振り分けられた IPv4 パケットを処理する
fn handleIp4(
    out: []u8,
    stdout: *Io.Writer,
    table: *const tcpipz.arp.Table,
    payload: []const u8,
) !?[]const u8 {
    const ip = tcpipz.ip;

    const packet = ip.parse(payload) catch |err| {
        try stdout.print("dropped ({s})\n", .{@errorName(err)});
        return null;
    };

    if (!ip.isForUs(packet)) {
        return null;
    }

    // todo
    // 上位層への振り分けをProtocolで行う
    _ = out;
    _ = table;

    return null;
}
