const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const tcpipz = @import("tcpipz");
const ethernet = tcpipz.ethernet;
const arp = tcpipz.arp;
const ip = tcpipz.ip;
const icmp = tcpipz.icmp;
const udp = tcpipz.udp;
const socket = tcpipz.socket;

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
    try stdout.print("Waiting for frames...\n\n", .{});
    try stdout.flush();

    var arp_table: arp.Table = .{};

    // このスタックが「開いている」ポート。カーネルの socket()/bind() にあたる
    var sockets: socket.Table = .{};
    try sockets.bind(7, socket.echo); // RFC 862
    try sockets.bind(9, socket.discard); // RFC 863

    var tx_buf: [ethernet.max_frame_len]u8 = undefined;
    var rx_buf: [2048]u8 = undefined;

    while (true) {
        const rx_frame = try tap.read(io, &rx_buf);
        const tx_frame = handleFrame(&tx_buf, &arp_table, &sockets, rx_frame) catch |err| switch (err) {
            // バッファ不足はこちらの設計ミス。捨てて動き続けると気づけないので落とす
            error.BufferTooSmall, error.PayloadTooLarge => return err,
            else => {
                try stdout.print("--- {d} bytes: dropped ({s}) ---\n", .{ rx_frame.len, @errorName(err) });
                try stdout.flush();
                continue;
            },
        };

        if (tx_frame) |frame| try tap.write(io, frame);
        try stdout.flush();
    }
}

/// カーネル側 tap0 の IP。このスタックから見た唯一の通信相手。
const kernel_ip: arp.Ip4 = .{ 192, 168, 70, 1 };

/// ! : error   捨てた - パースに失敗した不正なフレーム
/// ? : null    正常   - ただし返すものは無い（他人宛の ARP, IP パケットを捨てるのもこれ）
///   : []u8    正常   - 組み立てた応答フレーム。呼び出し側が TAP へ書く
fn handleFrame(
    tx_buf: []u8,
    arp_table: *arp.Table,
    sockets: *const socket.Table,
    rx_frame: []const u8,
) !?[]const u8 {
    const frame = try ethernet.parse(rx_frame);
    return switch (frame.ethertype) {
        .arp => try handleArp(tx_buf, arp_table, frame.payload),
        .ip4 => try handleIp4(tx_buf, arp_table, sockets, frame.payload),
        else => null, // IPv6 と未知の EtherType は黙って無視する
    };
}

fn handleArp(tx_buf: []u8, arp_table: *arp.Table, bytes: []const u8) !?[]const u8 {
    const packet = try arp.parse(bytes);

    // オペコードを見る前に学習する
    // 要求も応答も送信元の対応を運んでいるので、両方が学習の機会になる
    arp_table.put(packet.sender_ip, packet.sender_mac);

    // 応答（reply）はここで終わり — 学習が目的で、返すものは無い
    // 未知のオペコード（RARP など）にも答えない
    if (packet.oper != .request) return null;
    if (!std.mem.eql(u8, &packet.target_ip, &arp.our_ip)) return null;

    var arp_buf: [arp.packet_len]u8 = undefined;
    return try ethernet.build(tx_buf, .{
        .dst = packet.sender_mac,
        .src = ethernet.our_mac,
        .ethertype = .arp,
        .payload = try arp.build(&arp_buf, arp.replyTo(packet)),
    });
}

fn handleIp4(
    tx_buf: []u8,
    arp_table: *const arp.Table,
    sockets: *const socket.Table,
    bytes: []const u8,
) !?[]const u8 {
    const packet = try ip.parse(bytes);
    if (!ip.isForUs(packet)) return null;
    return switch (packet.protocol) {
        .icmp => try handleIcmp(tx_buf, arp_table, packet),
        .udp => try handleUdp(tx_buf, arp_table, sockets, packet),
        else => null,
    };
}

fn handleIcmp(tx_buf: []u8, arp_table: *const arp.Table, packet: ip.Packet) !?[]const u8 {
    const message = try icmp.parse(packet.payload);
    if (message.type != .echo_request) return null;
    var icmp_buf: [ethernet.mtu - ip.header_len_min]u8 = undefined;
    return try ip.output(
        tx_buf,
        arp_table,
        packet.src,
        .icmp,
        try icmp.build(&icmp_buf, icmp.replyTo(message)),
    );
}

/// 振り分けられた UDP データグラムを、宛先ポートに結びついたハンドラへ渡す
///
/// 応答は送信元と宛先のポートを入れ替えて返す — L4 が IP に足したものが
/// 実質ポート番号だけであることが、この 2 行に出ている
fn handleUdp(
    tx_buf: []u8,
    arp_table: *const arp.Table,
    sockets: *const socket.Table,
    packet: ip.Packet,
) !?[]const u8 {
    const datagram = try udp.parse(packet.payload, packet.src, packet.dst);

    // 閉じたポートは黙って捨てる。本来は ICMP Port Unreachable を返す (RFC 1122 4.1.3.1)
    const handler = sockets.lookup(datagram.dst_port) orelse return null;
    const reply = handler(datagram.payload) orelse return null;

    var udp_buf: [ethernet.mtu - ip.header_len_min]u8 = undefined;
    return try ip.output(tx_buf, arp_table, packet.src, .udp, try udp.build(
        &udp_buf,
        packet.src,
        datagram.dst_port,
        datagram.src_port,
        reply,
    ));
}

test "自分宛の ARP 要求には応答を返し、送信元を学習する" {
    const sender_mac: ethernet.Mac = .{ 0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c };
    const sender_ip: arp.Ip4 = .{ 192, 168, 70, 1 };

    var arp_buf: [arp.packet_len]u8 = undefined;
    var rx_buf: [ethernet.max_frame_len]u8 = undefined;
    const request = try ethernet.build(&rx_buf, .{
        .dst = ethernet.broadcast,
        .src = sender_mac,
        .ethertype = .arp,
        // requestFor は送信元が自分になるので、対向が尋ねてくる形を直接組む
        .payload = try arp.build(&arp_buf, .{
            .oper = .request,
            .sender_mac = sender_mac,
            .sender_ip = sender_ip,
            .target_mac = @splat(0),
            .target_ip = arp.our_ip,
        }),
    });

    var arp_table: arp.Table = .{};
    var sockets: socket.Table = .{};
    var tx_buf: [ethernet.max_frame_len]u8 = undefined;
    const reply = try arp.parse((try ethernet.parse(
        (try handleFrame(&tx_buf, &arp_table, &sockets, request)).?,
    )).payload);

    try std.testing.expectEqual(arp.Oper.reply, reply.oper);
    try std.testing.expectEqual(sender_mac, reply.target_mac);
    try std.testing.expectEqual(sender_mac, arp_table.lookup(sender_ip).?);
}

test "捨てたフレームは null ではなく error で返る" {
    var arp_table: arp.Table = .{};
    var sockets: socket.Table = .{};
    var tx_buf: [ethernet.max_frame_len]u8 = undefined;

    // 14 バイトに満たない = Ethernet ヘッダすら無い
    try std.testing.expectError(
        error.FrameTooShort,
        handleFrame(&tx_buf, &arp_table, &sockets, &.{0x00}),
    );
}

test "返すものが無いフレームは null で返る" {
    var arp_table: arp.Table = .{};
    var sockets: socket.Table = .{};
    var tx_buf: [ethernet.max_frame_len]u8 = undefined;

    var rx_buf: [ethernet.max_frame_len]u8 = undefined;
    const frame = try ethernet.build(&rx_buf, .{
        .dst = ethernet.our_mac,
        .src = .{ 0xde, 0xda, 0x6c, 0x00, 0x2b, 0x9c },
        .ethertype = .ip6, // 扱わないので無視される
        .payload = "",
    });

    try std.testing.expectEqual(null, try handleFrame(&tx_buf, &arp_table, &sockets, frame));
}
