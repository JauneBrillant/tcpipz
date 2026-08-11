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
    # 永続デバイスとして作る。スタックが TUNSETIFF で作ることもできるが、
    # それだとプロセス終了時に消えて IP の割り当てもやり直しになる
    ip tuntap add dev tap0 mode tap

    # カーネル側の IP。これで 192.168.70.0/24 宛を tap0 に流す経路ができる
    ip addr add 192.168.70.1/24 dev tap0

    # 作った直後は DOWN。上げないとカーネルは何も流さない
    ip link set tap0 up

    # L4 チェックサムのオフロードを無効化する。TAP には計算を肩代わりする
    # ハードウェアが無いので、有効なままだと未計算のフレームが届いて
    # 受信側の検証が落ちる（効いてくるのは UDP 以降）
    ethtool -K tap0 tx off
fi

exec "$@"
