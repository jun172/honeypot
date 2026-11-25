#!/bin/bash
set -euo pipefail

# ==============================================================================
# 世界の攻撃ボット・スキャナーが狙う主要45ポート（Web / 管理画面 / Proxy / DB / IoT系）
# ※注意: 管理用SSH（22番または22222番）は絶対にここに入れないこと！
# ==============================================================================
PORTS=(
  # --- 標準・代替HTTP / HTTPS / Proxy系 ---
  80 81 82 83 88 443 591 8000 8001 8008 8080 8081 8082 8088 8090 8181 8443 8880 8888 9000 9001 9080 9090 9443 10000
  # --- プロキシ・踏み台悪用探索系 ---
  1080 3128 8118 8123
  # --- 開発フレームワーク・管理パネル（Node / Python / Java / Docker / K8s） ---
  2375 3000 3001 4000 4200 4567 5000 5001 5601 7001 7002 9200
  # --- IoT・ルーター・カメラ・産業機器のWeb管理UI系 ---
  8089 8291 8728 37777
)

IMAGE_URI="asia-northeast1-docker.pkg.dev/honeypot-515503/cloud-run-source-deploy/honeypot-http:latest"

# ==============================================================================
# 1. ネットワーク（iptables）のガチガチ防御
# ==============================================================================
for p in "${PORTS[@]}"; do
  iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT
done

# ① GCPメタデータサーバー（169.254.169.254）へのSSRFアクセスを完全遮断
iptables -C DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || \
  iptables -I DOCKER-USER -d 169.254.169.254 -j DROP

# ② プライベートIP空間（GCP内部ネットワーク等）への横展開スキャンを完全遮断
for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  iptables -C DOCKER-USER -s 172.17.0.0/16 -d "$cidr" -j DROP 2>/dev/null || \
    iptables -I DOCKER-USER -s 172.17.0.0/16 -d "$cidr" -j DROP
done

# ③ コンテナからの新規外向き（アウトバウンド）通信をすべて遮断（踏み台・DDoS悪用防止）
iptables -C DOCKER-USER -s 172.17.0.0/16 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -I DOCKER-USER -s 172.17.0.0/16 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C DOCKER-USER -s 172.17.0.0/16 -j DROP 2>/dev/null || \
  iptables -A DOCKER-USER -s 172.17.0.0/16 -j DROP

# ==============================================================================
# 2. Dockerコンテナの起動（COS対応：書き込み可能な /tmp/.docker を使用）
# ==============================================================================
export DOCKER_CONFIG=/tmp/.docker
mkdir -p "$DOCKER_CONFIG"
/usr/bin/docker-credential-gcr configure-docker --registries=asia-northeast1-docker.pkg.dev

docker rm -f honeypot hp-nginx 2>/dev/null || true

PORT_ARGS=()
for p in "${PORTS[@]}"; do
  PORT_ARGS+=(-p "${p}:8080")
done

docker run -d \
  --name honeypot \
  --restart unless-stopped \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --pids-limit=128 \
  --ulimit nofile=4096:4096 \
  --ulimit nproc=128:128 \
  --memory=256m \
  --memory-swap=256m \
  --cpus=0.5 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --user 65534:65534 \
  "${PORT_ARGS[@]}" \
  --log-driver=gcplogs \
  "$IMAGE_URI"

echo "=== 起動完了：現在のコンテナ状態 ==="
docker ps
# （startup.sh の末尾に追加）
mkdir -p /tmp/pcap
docker rm -f hp-pcap hp-pcap-sync 2>/dev/null || true

# 1. パケット録画コンテナ（22番以外のTCPを10MBごとに保存）
docker run -d \
  --name hp-pcap \
  --restart unless-stopped \
  --net=host \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v /tmp/pcap:/pcap \
  nicolaka/netshoot \
  tcpdump -i any -nn -s 0 "tcp and not port 22" -C 10 -W 10 -w /pcap/capture.pcap

# 2. 5分ごとに溜まったpcapをGCSへ自動アップロード＆ローカル削除する軽量コンテナ
docker run -d \
  --name hp-pcap-sync \
  --restart unless-stopped \
  -v /tmp/pcap:/pcap \
  google/cloud-sdk:slim \
  bash -c 'while true; do sleep 604800; for f in /pcap/capture.pcap*; do [ -f "$f" ] && gcloud storage cp "$f" gs://honeypot-archive-515503/pcap/$(hostname)_$(date +%Y%m%d_%H%M%S)_$(basename "$f") && rm -f "$f"; done; done'
