//! tcpipz — 自作 TCP/IP スタックのライブラリルート。
//! 各プロトコル層のモジュールをここから公開する。

pub const hexdump = @import("hexdump.zig");

test {
    // 参照したモジュールのテストをテストランナーに含める
    _ = hexdump;
}
