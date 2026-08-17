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

    // 学習したアドレスの置き場。以降このスタックが出す全てのフレームが、
    // 宛先 MAC を決めるためにここを引くことになる。
    var table: tcpipz.arp.Table = .{};

    // 起動時にこちらから尋ねてみる。応答が返ればテーブルに 1 件載る。
    // 誰も要求してこなくても、自分から会話を始められることの確認。
    // 持ち主が分からないので宛先はブロードキャスト — 全員に配り、当事者だけが答える。
    try sendArp(io, tap, tcpipz.ethernet.broadcast, tcpipz.arp.requestFor(kernel_ip));

    // コメントで確認 - あとで削除する -
    try stdout.print("asked: who-has ", .{});
    try tcpipz.arp.formatIp(stdout, kernel_ip);
    try stdout.print("\n", .{});
    //

    try stdout.print("Waiting for frames...\n", .{});
    try stdout.flush();

    // MTU 1500 + Ethernet ヘッダ 14 に十分な受信バッファ。
    //
    // 受信したフレームの実体はこの配列にしか無い。各層の parse はコピーを作らず、
    // 「バッファのどこからどこまでが自分の担当か」を切り直しているだけ:
    //
    //   ┌─ Ethernet 14 ─┬─ IPv4 header 20 ─┬─ ICMP 64 ─┬── 未使用 ──┐
    //   0              14                 34          98          2048
    //   │               │                  └ ip.Packet.payload   = buf[34..98]
    //   │               └──────────────────── ethernet.Frame.payload = buf[14..98]
    //   └──────────────────────────────────── tap.read の戻り値      = buf[0..98]
    //
    // このため、パース結果のスライスが有効なのは**次の read までの間だけ**。
    // 跨いで残したいものは値をコピーする必要がある。arp.Table のエントリが
    // Ip4 / Mac（固定長配列 = 値）なのはそのため — put した時点でコピーされる。
    var buf: [2048]u8 = undefined;

    while (true) {
        const bytes = try tap.read(io, &buf); // ブロッキング呼び出し
        try handleFrame(io, tap, stdout, &table, bytes);
        try stdout.flush();
    }
}

/// カーネル側 tap0 の IP。このスタックから見た唯一の通信相手。
const kernel_ip: tcpipz.arp.Ip4 = .{ 192, 168, 70, 1 };

/// ARP パケットを Ethernet フレームに包んで送る。
fn sendArp(io: Io, tap: tcpipz.Tap, dst: tcpipz.ethernet.Mac, packet: tcpipz.arp.Packet) !void {
    const arp = tcpipz.arp;
    const ethernet = tcpipz.ethernet;

    var arp_buf: [arp.packet_len]u8 = undefined;
    var frame_buf: [ethernet.header_len + arp.packet_len]u8 = undefined;
    const frame = try ethernet.build(&frame_buf, .{
        .dst = dst,
        .src = ethernet.our_mac,
        .ethertype = .arp,
        .payload = try arp.build(&arp_buf, packet),
    });
    try tap.write(io, frame);
}

/// 受信したフレームを 1 つ処理する。
/// 上位層への振り分けは EtherType で行う。この形は以降の層でも繰り返される。
fn handleFrame(
    io: Io,
    tap: tcpipz.Tap,
    stdout: *Io.Writer,
    table: *tcpipz.arp.Table,
    bytes: []const u8,
) !void {
    const ethernet = tcpipz.ethernet;

    const frame = ethernet.parse(bytes) catch |err| {
        try stdout.print("\n--- {d} bytes: dropped ({s}) ---\n", .{ bytes.len, @errorName(err) });
        return;
    };

    switch (frame.ethertype) {
        .arp => {
            try stdout.print("frame received : ethertype = arp\n", .{});
            try handleArp(io, tap, stdout, table, frame.payload);
            return;
        },
        .ip4 => {
            try stdout.print("frame received : ethertype = ipv4\n", .{});
            try handleIp4(stdout, frame.payload);
            return;
        },
        .ip6 => return,
        else => return,
    }
}

/// 受信した IPv4 パケットを tcpdump 風に表示する。
/// 上位層への振り分けはプロトコル番号で行う — EtherType と同じ構造が 1 段上でも繰り返される。
fn handleIp4(stdout: *Io.Writer, payload: []const u8) !void {
    const ip = tcpipz.ip;

    const packet = ip.parse(payload) catch |err| {
        try stdout.print("dropped ({s})\n", .{@errorName(err)});
        return;
    };

    // 所有していない IP 宛のパケットに答えてはいけない。ARP のときと同じ判断
    if (!ip.isForUs(packet)) {
        try stdout.print("not for us: ", .{});
        try ip.formatAddr(stdout, packet.dst);
        try stdout.print("\n", .{});
        return;
    }

    try ip.formatAddr(stdout, packet.src);
    try stdout.print(" > ", .{});
    try ip.formatAddr(stdout, packet.dst);
    try stdout.print(": proto={s} ttl={d} len={d} payload={d}B\n", .{
        @tagName(packet.protocol),
        packet.ttl,
        packet.total_len,
        packet.payload.len,
    });

    // 上位層はまだ無い。ICMP は Step 11 から
}

/// 受信した ARP を tcpdump 風に表示し、自分の IP 宛の要求には応答を返す。
fn handleArp(
    io: Io,
    tap: tcpipz.Tap,
    stdout: *Io.Writer,
    table: *tcpipz.arp.Table,
    payload: []const u8,
) !void {
    const arp = tcpipz.arp;
    const ethernet = tcpipz.ethernet;

    const packet = arp.parse(payload) catch |err| {
        try stdout.print("dropped ({s})\n", .{@errorName(err)});
        return;
    };

    // 要求にも応答にも送信元のアドレス対が入っている。相手が話しかけてきた時点で
    // 1 件学習できる — 自分から尋ねなくてもテーブルは埋まっていく。
    //
    // RFC 826 はもう少し厳しく、「既知の IP なら更新、新規追加は自分宛のときだけ」
    // としている。無関係なブロードキャストでテーブルが埋まるのを防ぐためだが、
    // 対向がカーネル 1 台の TAP リンクではその状況が起きない。
    table.put(packet.sender_ip, packet.sender_mac);
    try stdout.print("learned: ", .{});
    try arp.formatIp(stdout, packet.sender_ip);
    try stdout.print(" is at ", .{});
    try ethernet.formatMac(stdout, packet.sender_mac);
    try stdout.print("  ({d}/{d} entries)\n", .{ table.len, arp.Table.capacity });

    // 自分宛の要求だけに応答する。他ホスト宛への要求も（ブロードキャストなので）
    // 届くが、所有していない IP に答えてはいけない
    if (packet.oper != .request) return;
    if (!std.mem.eql(u8, &packet.target_ip, &arp.our_ip)) return;

    // 応答はブロードキャストではなく、尋ねてきた本人へユニキャストで返す
    try sendArp(io, tap, packet.sender_mac, arp.replyTo(packet));

    try stdout.print("replied: ", .{});
    try arp.formatIp(stdout, arp.our_ip);
    try stdout.print(" is at ", .{});
    try ethernet.formatMac(stdout, ethernet.our_mac);
    try stdout.print("\n", .{});
}
