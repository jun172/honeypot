#!/bin/bash
set -euo pipefail

IMAGE_URI="asia-northeast1-docker.pkg.dev/honeypot-515503/cloud-run-source-deploy/honeypot-http:latest"
NGINX_IMAGE="nginx:1.27-alpine"
GCS_BUCKET="gs://honeypot-archive-515503"
CERT_DIR="/tmp/nginx-certs"
NGINX_CONF_DIR="/tmp/nginx-conf"
PCAP_DIR="/tmp/pcap"

# ==============================================================================
# 外部公開ポート定義（重複なし・管理用SSHポートは絶対に含めないこと）
# ==============================================================================
HTTP_PORTS=(80 8080)
HTTPS_PORTS=(443 8443)

EXTRA_PORTS=(
  # --- 追加の代替HTTP / HTTPS / Proxy系 ---
  81 82 83 84 85 88 89 300 591 593 2082 2083 2086 2087 2095 2096
  8000 8001 8002 8003 8008 8009 8010 8081 8082 8083 8084 8085 8086 8087 8088 8090 8091 8099
  8180 8181 8444 8800 8880 8881 8888 9000 9001 9002 9080 9081 9090 9091 9443 10000 10443 18080 28080

  # --- プロキシ・SOCKS・踏み台探索系 ---
  1080 3128 3129 8080 8118 8123 9050 9051

  # --- 開発フレームワーク・API・管理パネル（Node / Python / Java / Go / Docker / K8s / CI） ---
  2375 2376 2379 2380 3000 3001 3002 3003 4000 4040 4200 4567 4848 5000 5001 5005 5601 6443 7000 7001 7002
  7070 7474 7687 8005 8006 8069 8096 8161 8200 8333 8500 8834 8983 9009 9042 9092 9100 9200 9300 9418 11211 15672 27018

  # --- DB / キャッシュ / メッセージブローカー / ストレージ系 ---
  1433 1521 2049 3306 3307 4369 5432 5433 5672 5900 5901 5984 6379 6380 8086 11212 27017 27019

  # --- IoT・ルーター・カメラ・VPN・産業機器・レガシー管理UI系 ---
  21 23 25 53 69 110 111 135 139 161 389 445 502 512 513 514 554 636 873 993 995 1723 1883 1900 5353
  7547 8089 8291 8728 8729 8883 9527 10250 37777 49152 50000 55555
)

# ==============================================================================
# 1. ネットワーク（iptables）設定
# ==============================================================================
for p in "${HTTP_PORTS[@]}" "${HTTPS_PORTS[@]}" "${EXTRA_PORTS[@]}"; do
  iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT
done

iptables -F DOCKER-USER 2>/dev/null || true
iptables -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A DOCKER-USER -d 169.254.169.254 -j DROP
for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  iptables -A DOCKER-USER -d "$cidr" -j DROP
done
iptables -A DOCKER-USER -j DROP

# ==============================================================================
# 2. 自己署名証明書＆ nginx.conf の配置
# ==============================================================================
mkdir -p "$CERT_DIR" "$NGINX_CONF_DIR" "$PCAP_DIR"
chmod 700 "$CERT_DIR"

if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -days 365 \
    -subj "/C=JP/ST=Hyogo/L=Kobe/O=Honeypot/CN=_"
  chmod 600 "$CERT_DIR/key.pem"
  chmod 644 "$CERT_DIR/cert.pem"
fi

cat <<'EOF' > "$NGINX_CONF_DIR/nginx.conf"
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    server_tokens off;

    log_format honeypot_json escape=json '{'
        '"source": "nginx_proxy",'
        '"ts": "$time_iso8601",'
        '"src_ip": "$remote_addr",'
        '"src_port": "$remote_port",'
        '"dst_port": "$server_port",'
        '"scheme": "$scheme",'
        '"ssl_protocol": "$ssl_protocol",'
        '"ssl_cipher": "$ssl_cipher",'
        '"ssl_server_name": "$ssl_server_name",'
        '"method": "$request_method",'
        '"uri": "$request_uri",'
        '"status": "$status",'
        '"user_agent": "$http_user_agent",'
        '"content_type": "$http_content_type",'
        '"body": "$request_body"'
    '}';

    client_max_body_size 2m;
    client_body_buffer_size 128k;

    limit_req_zone $binary_remote_addr zone=hp_limit:10m rate=10r/s;
    limit_req_status 429;

    access_log /dev/stdout honeypot_json;
    error_log  /dev/stderr warn;

    upstream honeypot_backend {
        server honeypot:8080;
    }

    server {
        listen 80;
        listen 8080;
        server_name _;

        add_header X-Powered-By "PHP/8.2.0" always;

        location / {
            limit_req zone=hp_limit burst=20 nodelay;
            proxy_pass http://honeypot_backend;
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Real-Port $remote_port;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_set_header X-Original-Port $server_port;
            proxy_set_header X-SSL-Protocol $ssl_protocol;
            proxy_set_header X-SSL-Cipher $ssl_cipher;
            proxy_set_header X-SSL-Server-Name $ssl_server_name;
            proxy_connect_timeout 5s;
            proxy_send_timeout 10s;
            proxy_read_timeout 10s;
        }
    }

    server {
        listen 443 ssl;
        listen 8443 ssl;
        server_name _;

        ssl_certificate     /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;

        add_header X-Powered-By "PHP/8.2.0" always;

        location / {
            limit_req zone=hp_limit burst=20 nodelay;
            proxy_pass http://honeypot_backend;
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Real-Port $remote_port;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_set_header X-Original-Port $server_port;
            proxy_set_header X-SSL-Protocol $ssl_protocol;
            proxy_set_header X-SSL-Cipher $ssl_cipher;
            proxy_set_header X-SSL-Server-Name $ssl_server_name;
            proxy_connect_timeout 5s;
            proxy_send_timeout 10s;
            proxy_read_timeout 10s;
        }
    }
}
EOF

# ==============================================================================
# 3. Docker ネットワークとコンテナ起動（COS対応: /tmp/.docker を使用）
# ==============================================================================
export DOCKER_CONFIG=/tmp/.docker
mkdir -p "$DOCKER_CONFIG"
/usr/bin/docker-credential-gcr configure-docker --registries=asia-northeast1-docker.pkg.dev

docker pull "$IMAGE_URI"
docker pull "$NGINX_IMAGE"

docker network inspect hp-net >/dev/null 2>&1 || docker network create hp-net
docker rm -f honeypot hp-nginx hp-pcap hp-pcap-sync 2>/dev/null || true

EXTRA_PORT_ARGS=()
for p in "${EXTRA_PORTS[@]}"; do
  EXTRA_PORT_ARGS+=(-p "${p}:8080")
done

docker run -d \
  --name honeypot \
  --network hp-net \
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
  "${EXTRA_PORT_ARGS[@]}" \
  --log-driver=gcplogs \
  "$IMAGE_URI"

docker run -d \
  --name hp-nginx \
  --network hp-net \
  --restart unless-stopped \
  -p 80:80 \
  -p 8080:8080 \
  -p 443:443 \
  -p 8443:8443 \
  -v "$NGINX_CONF_DIR/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$CERT_DIR:/etc/nginx/certs:ro" \
  --log-driver=gcplogs \
  "$NGINX_IMAGE"

# ==============================================================================
# 4. パケット録画（tcpdump）＆ 1時間ごとの GCS バックアップ
# ==============================================================================
docker run -d \
  --name hp-pcap \
  --restart unless-stopped \
  --net=host \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v "$PCAP_DIR:/pcap" \
  nicolaka/netshoot \
  tcpdump -i any -nn -s 0 "tcp and not port 22" -C 50 -W 20 -w /pcap/capture.pcap

docker run -d \
  --name hp-pcap-sync \
  --restart unless-stopped \
  -v "$PCAP_DIR:/pcap" \
  google/cloud-sdk:slim \
  bash -c 'while true; do sleep 3600; for f in /pcap/capture.pcap*; do [ -f "$f" ] && gcloud storage cp "$f" "'"$GCS_BUCKET"'/pcap/$(hostname)_$(date +%Y%m%d_%H%M%S)_$(basename "$f")" && rm -f "$f"; done; done'

echo "=== 起動完了：現在のコンテナ状態 ==="
docker ps

DB_DIR="/tmp/honeypot-db"
mkdir -p "$DB_DIR"
# コンテナ内ユーザー(65534:65534)からSQLiteファイルを読み書きできるようにする
chown -R 65534:65534 "$DB_DIR"
chmod 700 "$DB_DIR"

# 起動時にGCSの最新DBがあれば復元
if gcloud storage ls "${GCS_BUCKET}/sqlite/portal_news_latest.db" >/dev/null 2>&1; then
  gcloud storage cp "${GCS_BUCKET}/sqlite/portal_news_latest.db" "${DB_DIR}/portal_news.db"
  chown 65534:65534 "${DB_DIR}/portal_news.db"
fi

#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-honeypot-515503}"
OUT_DIR="${1:-/opt/honeypot}"
mkdir -p "$OUT_DIR"

# 1. コピペ用の検索クエリ集をファイル出力
cat <<'EOF' > "${OUT_DIR}/cloud_logging_queries.txt"
# [1] 攻撃手法・Stage2 URL の抽出
jsonPayload.event_type="http_request"
(
  jsonPayload.threat_intel.attack_techniques:("sqli" OR "xss" OR "rce_cmd_injection" OR "nextjs_rsc_rce" OR "path_traversal" OR "ssrf_cloud_metadata")
  OR jsonPayload.outcome="stage2_url_captured"
)

# [2] TLS情報・通信フィンガープリントの絞り込み
jsonPayload.event_type="http_request"
jsonPayload.tls_info.scheme="https"
jsonPayload.tls_info.ssl_protocol=~"TLSv1\.(2|3)"
jsonPayload.comm_fingerprint.signals:("browser_ua_without_sec_fetch" OR "minimal_script_headers" OR "rapid_request_cadence")

# [3] 多段デコード結果・外部IP・C2候補の検知
jsonPayload.event_type="http_request"
(
  jsonPayload.threat_intel.c2_candidates.decoded_base64_count > 0
  OR jsonPayload.threat_intel.c2_candidates.decoded_hex_count > 0
  OR jsonPayload.threat_intel.c2_candidates.ips.is_public=true
)
-jsonPayload.client_ip=~"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"

# [4] 脆弱性デコイ（SQLi / XSS / IDOR / LFI / SSRF / CMDi）へのヒット
jsonPayload.event_type="http_request"
jsonPayload.outcome:(
  "sqli_xss_search_probe"
  OR "stored_xss_comment_post"
  OR "sqli_or_valid_login_success"
  OR "idor_user_profile_dump"
  OR "lfi_passwd_dump"
  OR "lfi_sqlite_db_dump"
  OR "ssrf_metadata_bait"
  OR "cmdi_ping_bait"
)
EOF

# 2. Cloud Logging のログベース指標を作成（既存ならスキップ）
gcloud logging metrics create honeypot_attack_hits \
  --project="$PROJECT_ID" \
  --description="Count of detected attack techniques or stage2 URLs" \
  --log-filter='jsonPayload.event_type="http_request" AND (jsonPayload.threat_intel.attack_techniques:* OR jsonPayload.outcome="stage2_url_captured")' \
  2>/dev/null || true

echo "Saved queries to ${OUT_DIR}/cloud_logging_queries.txt"