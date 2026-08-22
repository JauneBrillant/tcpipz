//!    --- TCP Header ---
//!   0            4            8                       16                       24                      31
//!   ┌─────────────────────────────────────────────────┬─────────────────────────────────────────────────┐
//!   │                   source port                   │                destination port                 │
//!   ├─────────────────────────────────────────────────┴─────────────────────────────────────────────────┤
//!   │                                          sequence number                                          │
//!   ├───────────────────────────────────────────────────────────────────────────────────────────────────┤
//!   │                                       acknowledgment number                                       │
//!   ├────────────┬────────────┬───────────────────────┬─────────────────────────────────────────────────┤
//!   │data offset │  reserved  │     control flags     │                     window                      │
//!   ├────────────┴────────────┴───────────────────────┼─────────────────────────────────────────────────┤
//!   │                    checksum                     │                 urgent pointer                  │
//!   ├─────────────────────────────────────────────────┴─────────────────────────────────────────────────┤
//!   │                                       options (0-40 bytes)                                        │
//!   ├───────────────────────────────────────────────────────────────────────────────────────────────────┤
//!   │                                              payload                                              │
//!   └───────────────────────────────────────────────────────────────────────────────────────────────────┘

const std = @import("std");
const hexdump = @import("hexdump.zig");
const checksum = @import("checksum.zig");
const ip = @import("ip.zig");

pub const header_len_min = 20;
pub const header_len_max = 60;

/// 制御ビット 1 バイト
/// 宣言順が下位ビットから上位ビットへ対応する
pub const Flags = packed struct(u8) {
    /// 送るデータはもう無い。片方向のクローズ
    fin: bool = false,
    /// 接続を開く。シーケンス空間を 1 消費する
    syn: bool = false,
    /// 接続を叩き切る。応答を期待しない
    rst: bool = false,
    /// 溜めずにすぐアプリへ渡せ
    psh: bool = false,
    /// ack フィールドが有効。最初の SYN 以外は基本的に立っている
    ack: bool = false,
    /// 緊急ポインタが有効。ほぼ使われない
    urg: bool = false,
    /// 輻輳通知 (ECN)。実装しない
    ece: bool = false,
    cwr: bool = false,
};

pub const Segment = struct {
    src_port: u16,
    dst_port: u16,
    /// このセグメントの先頭バイトの位置。SYN / FIN もそれぞれ 1 消費する
    seq: u32,
    /// 「次に期待するバイト位置」。flags.ack が立っているときだけ有効
    ack: u32,
    /// data offset をバイト長に直したもの（20〜60）
    header_len: u8,
    flags: Flags,
    /// 受信側があと何バイト受け取れるか。フロー制御が後付けではなく
    /// 設計の中核であることが、固定ヘッダに席があることに表れている
    window: u16,
    checksum: u16,
    urgent: u16,
    /// ヘッダ末尾の可変長領域。今は読み飛ばすだけ（MSS を読むのは Step 19）
    options: []const u8,
    payload: []const u8,
};

pub const ParseError = error{
    SegmentTooShort,
    InvalidDataOffset,
    BadChecksum,
};

/// TCP セグメントをパースする
pub fn parse(bytes: []const u8, src: ip.Addr, dst: ip.Addr) ParseError!Segment {
    if (bytes.len < header_len_min) return error.SegmentTooShort;

    // 上位 4bit が data offset。下位 4bit は予約領域なので捨てる
    // data offset は 32bit ワード長なので 4 倍する
    const header_len: u8 = (bytes[12] >> 4) * 4;
    if (header_len < header_len_min) return error.InvalidDataOffset;
    if (bytes.len < header_len) return error.InvalidDataOffset;

    // 長さは IP から渡された bytes.len そのもの。TCP ヘッダには書かれていない
    const pseudo = checksum.pseudoHeader(src, dst, @intFromEnum(ip.Protocol.tcp), @intCast(bytes.len));
    if (!checksum.verifyWithPseudo(pseudo, bytes)) return error.BadChecksum;

    return .{
        .src_port = hexdump.readU16(bytes[0..2]),
        .dst_port = hexdump.readU16(bytes[2..4]),
        .seq = hexdump.readU32(bytes[4..8]),
        .ack = hexdump.readU32(bytes[8..12]),
        .header_len = header_len,
        .flags = @bitCast(bytes[13]),
        .window = hexdump.readU16(bytes[14..16]),
        .checksum = hexdump.readU16(bytes[16..18]),
        .urgent = hexdump.readU16(bytes[18..20]),
        .options = bytes[header_len_min..header_len],
        .payload = bytes[header_len..],
    };
}

/// このセグメントがシーケンス空間で消費する長さ
///
/// SYN と FIN はデータを 1 バイトも運ばないのに 1 消費する。だから SYN への
/// 応答が `seq + 1` を ACK する。この 1 が無いと、SYN が届いたことを
/// データの到達と同じ仕組みで確認できない
pub fn seqLen(segment: Segment) u32 {
    return @as(u32, @intCast(segment.payload.len)) +
        @intFromBool(segment.flags.syn) +
        @intFromBool(segment.flags.fin);
}

const testing = std.testing;

const sample_src: ip.Addr = .{ 192, 168, 70, 1 };
const sample_dst: ip.Addr = .{ 192, 168, 70, 2 };

/// `nc 192.168.70.2 8080` が投げてきた SYN の TCP 部分（実キャプチャ）。
/// tcpdump の解釈: seq 2884037473, win 64240,
/// options [mss 1460,sackOK,TS val 2815587851 ecr 0,nop,wscale 7]
const sample_syn = [_]u8{
    0xeb, 0xc2, // 送信元ポート 60354（カーネルのエフェメラルポート）
    0x1f, 0x90, // 宛先ポート 8080
    0xab, 0xe6, 0xeb, 0x61, // seq
    0x00, 0x00, 0x00, 0x00, // ack（SYN には ack フラグが無いので未使用）
    0xa0, // data offset 10 ワード = 40 バイト
    0x02, // flags: SYN のみ
    0xfa, 0xf0, // window 64240
    0x7f, 0x41, // checksum
    0x00, 0x00, // urgent pointer
    // --- options 20 バイト ---
    0x02, 0x04, 0x05, 0xb4, // MSS 1460
    0x04, 0x02, // SACK permitted
    0x08, 0x0a, 0xa7, 0xd2, 0x76, 0x0b, 0x00, 0x00, 0x00, 0x00, // Timestamps
    0x01, // NOP（次を 4 バイト境界に揃えるための詰め物）
    0x03, 0x03, 0x07, // Window scale 7
};

/// オプション無し (data offset 5) + ペイロード "hi" の ACK。
/// 実キャプチャの SYN からオプションを外してチェックサムを計算し直したもの
const sample_ack = [_]u8{
    0xeb, 0xc2, 0x1f, 0x90,
    0xab, 0xe6, 0xeb, 0x62,
    0x11, 0x22, 0x33, 0x44,
    0x50, // data offset 5 ワード = 20 バイト
    0x18, // flags: ACK + PSH
    0xfa,
    0xf0,
    0x58,
    0x19,
    0x00,
    0x00,
    'h',
    'i',
};

test "実際の SYN をパースする" {
    const segment = try parse(&sample_syn, sample_src, sample_dst);

    try testing.expectEqual(@as(u16, 60354), segment.src_port);
    try testing.expectEqual(@as(u16, 8080), segment.dst_port);
    try testing.expectEqual(@as(u32, 2884037473), segment.seq);
    try testing.expectEqual(@as(u32, 0), segment.ack);
    try testing.expectEqual(@as(u8, 40), segment.header_len);
    try testing.expectEqual(@as(u16, 64240), segment.window);
    try testing.expectEqual(@as(u16, 0), segment.urgent);

    // SYN だけが立っている
    try testing.expectEqual(Flags{ .syn = true }, segment.flags);

    try testing.expectEqual(@as(usize, 20), segment.options.len);
    try testing.expectEqual(@as(usize, 0), segment.payload.len);
}

test "flags のビット割り当てを実バイトで固定する" {
    // packed struct のビット順は宣言順（LSB 始まり）。実データで裏を取る
    try testing.expectEqual(Flags{ .syn = true }, @as(Flags, @bitCast(@as(u8, 0x02))));
    try testing.expectEqual(Flags{ .ack = true }, @as(Flags, @bitCast(@as(u8, 0x10))));
    try testing.expectEqual(Flags{ .fin = true, .ack = true }, @as(Flags, @bitCast(@as(u8, 0x11))));
    try testing.expectEqual(Flags{ .rst = true, .ack = true }, @as(Flags, @bitCast(@as(u8, 0x14))));
    try testing.expectEqual(@as(u8, 0x18), @as(u8, @bitCast(Flags{ .psh = true, .ack = true })));
}

test "オプション無し・ペイロードありをパースする" {
    const segment = try parse(&sample_ack, sample_src, sample_dst);

    try testing.expectEqual(@as(u8, 20), segment.header_len);
    try testing.expectEqual(@as(usize, 0), segment.options.len);
    try testing.expectEqualStrings("hi", segment.payload);
    try testing.expectEqual(Flags{ .ack = true, .psh = true }, segment.flags);
    try testing.expectEqual(@as(u32, 0x11223344), segment.ack);
}

test "payload と options は入力スライスへの参照" {
    // options はヘッダ末尾、payload はその先。どちらもコピーしていない
    const syn = try parse(&sample_syn, sample_src, sample_dst);
    try testing.expectEqual(
        @intFromPtr(&sample_syn[header_len_min]),
        @intFromPtr(syn.options.ptr),
    );

    const ack = try parse(&sample_ack, sample_src, sample_dst);
    try testing.expectEqual(
        @intFromPtr(&sample_ack[header_len_min]),
        @intFromPtr(ack.payload.ptr),
    );
}

test "宛先 IP が違えばチェックサムが落ちる" {
    // 疑似ヘッダが効いていることの確認。バイト列は 1 ビットも変えていない
    try testing.expectError(
        error.BadChecksum,
        parse(&sample_syn, sample_src, .{ 192, 168, 70, 9 }),
    );
}

test "TCP ではチェックサム 0 も許されない" {
    // UDP と違い「未計算」の逃げ道が無い
    var segment = sample_ack;
    hexdump.writeU16(segment[16..18], 0);
    try testing.expectError(error.BadChecksum, parse(&segment, sample_src, sample_dst));
}

test "1 バイト壊れると検証が落ちる" {
    var segment = sample_ack;
    segment[20] = 'H'; // payload の 'h'
    try testing.expectError(error.BadChecksum, parse(&segment, sample_src, sample_dst));
}

test "ヘッダに満たない入力はエラー" {
    try testing.expectError(
        error.SegmentTooShort,
        parse(sample_syn[0 .. header_len_min - 1], sample_src, sample_dst),
    );
}

test "data offset が 5 未満ならエラー" {
    var segment = sample_ack;
    segment[12] = 4 << 4; // 16 バイト — ヘッダが自分自身より短いことになる
    try testing.expectError(error.InvalidDataOffset, parse(&segment, sample_src, sample_dst));
}

test "data offset が入力を越えていればエラー" {
    var segment = sample_ack;
    segment[12] = 15 << 4; // 60 バイト。手元には 22 バイトしかない
    try testing.expectError(error.InvalidDataOffset, parse(&segment, sample_src, sample_dst));
}

test "SYN と FIN はシーケンス空間を 1 消費する" {
    const syn = try parse(&sample_syn, sample_src, sample_dst);
    try testing.expectEqual(@as(u32, 1), seqLen(syn)); // データ 0 バイトでも 1

    const ack = try parse(&sample_ack, sample_src, sample_dst);
    try testing.expectEqual(@as(u32, 2), seqLen(ack)); // "hi" の 2 バイトだけ
}
