const std = @import("std");
const Io = std.Io;

const tcpipz = @import("tcpipz");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    // 動作確認用: サンプルの ARP 要求フレーム（Ethernet ヘッダ 14 + ARP 28 バイト）。
    // Step 3 で TAP から読んだ実フレームに置き換わる。
    const sample_arp_request = [_]u8{
        // Ethernet: 宛先 MAC (ブロードキャスト) / 送信元 MAC / EtherType (ARP)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06,
        // ARP: 誰か 192.168.70.2 の MAC を教えて（送信元 192.168.70.1）
        0x00, 0x01, 0x08, 0x00,
        0x06, 0x04, 0x00, 0x01, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x01, 0xc0, 0xa8,
        0x46, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xc0, 0xa8, 0x46, 0x02,
    };
    try tcpipz.hexdump.dump(stdout, &sample_arp_request);

    try stdout.flush();
}
