//! tcpipz — 自作 TCP/IP スタックのライブラリルート。
//! 各プロトコル層のモジュールをここから公開する。

pub const hexdump = @import("hexdump.zig");
pub const checksum = @import("checksum.zig");
pub const ethernet = @import("ethernet.zig");
pub const arp = @import("arp.zig");
pub const Tap = @import("Tap.zig");

test {
    // 参照したモジュールのテストをテストランナーに含める。
    // Tap.zig は I/O のみでユニットテストを持たない（Linux 専用のため
    // ホスト側のテスト実行でコンパイルされないよう、ここには含めない）
    _ = hexdump;
    _ = checksum;
    _ = ethernet;
    _ = arp;
}
