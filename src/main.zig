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

    try stdout.print("tap0 を開いた。フレーム待機中... (Ctrl-C で終了)\n", .{});
    try stdout.flush();

    // MTU 1500 + Ethernet ヘッダ 14 に十分な受信バッファ
    var buf: [2048]u8 = undefined;
    while (true) {
        const frame = try tap.read(io, &buf);
        try stdout.print("\n--- {d} bytes ---\n", .{frame.len});
        try tcpipz.hexdump.dump(stdout, frame);
        try stdout.flush();
    }
}
