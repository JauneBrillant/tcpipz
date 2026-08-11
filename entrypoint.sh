#!/bin/sh
# コンテナ起動時に tap0 を用意する。
#
# TAP はカーネルの状態であってファイルシステムではないため、Dockerfile の
# ビルド時には作れない（ビルドコンテナには /dev/net/tun も NET_ADMIN も無い）。
# 起動時に走るこのスクリプトで作る。
#
# ネットワーク名前空間はコンテナ内で共有されるので、ここで作れば後から
# docker compose exec で入ったシェルからも見える。

set -e

if ! ip link show tap0 >/dev/null 2>&1; then
    # tap0 という名前の TUN/TAP デバイスを作る。
    # mode tap は L2、つまり Ethernet フレームが丸ごと流れてくる指定。
    # mode tun にすると Ethernet ヘッダの無い IP パケットが届くので、
    # Ethernet の解析から自作するこのプロジェクトでは tap でなければならない
    # （Tap.zig の IFF_TAP と同じ指定を、コマンド側から行っている）。
    # add で作ったデバイスは永続。スタックの TUNSETIFF でも作れるが、
    # それだとプロセス終了時に消えて IP の割り当てもやり直しになる
    ip tuntap add dev tap0 mode tap

    # tap0 に 192.168.70.1/24 を付与する。
    # /24 なので先頭 24 ビットが同じ 192.168.70.0〜255 の範囲が
    # 「tap0 の先に直接いる」とみなされ、カーネルが経路表にエントリを作る。
    # 自作スタックの 192.168.70.2 もこの範囲に入るので tap0 に流れる
    ip addr add 192.168.70.1/24 dev tap0

    # tap0 インターフェースを管理上 UP にする。作った直後は DOWN で、
    # このままだとアドレスを付けてもカーネルは何も流さない。
    #
    # ここで立つのは管理状態の UP だけで、通信可能になるわけではない。
    # 実際に流れ始めるにはキャリア（LOWER_UP）も要り、そちらは自作のスタックが
    # /dev/net/tun の fd を開いている間しか立たない。ip link show の見え方:
    #   自作スタック未起動: <NO-CARRIER,...,UP>  state DOWN
    #   自作スタック起動中: <...,UP,LOWER_UP>    state UP
    # UP はどちらでも立っていて、LOWER_UP だけが入れ替わる
    ip link set tap0 up

    # L4 チェックサムのオフロードを無効化する。TAP には計算を肩代わりする
    # ハードウェアが無いので、有効なままだと未計算のフレームが届いて
    # 受信側の検証が落ちる（効いてくるのは UDP 以降）
    ethtool -K tap0 tx off
fi

exec "$@"
