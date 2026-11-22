#!/usr/bin/env bash

TYPE=$1
DELAY=${2:-0.08}

mkdir -p shared-logs
touch shared-logs/linux_auth.log shared-logs/windows_sysmon.json shared-logs/web_access.log

feed_stream() {
    SRC=$1
    DST=$2
    if [ -f "$SRC" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            [ -z "$line" ] && continue
            echo "$line" >> "$DST"
            sleep "$DELAY"
        done < "$SRC"
    fi
}

live_docker_attack() {
    sudo docker run --rm --privileged --pid=host alpine nsenter --target 1 --mount --uts --ipc --net --pid -- hostname >/dev/null 2>&1
    sudo tail -n 5 /var/log/auth.log | grep "nsenter" >> shared-logs/linux_auth.log
}

case "$TYPE" in
    docker)
        feed_stream "datasets/docker_escape.log" "shared-logs/linux_auth.log"
        ;;
    docker_live)
        live_docker_attack
        ;;
    amsi)
        feed_stream "datasets/windows_amsi_bypass.json" "shared-logs/windows_sysmon.json"
        ;;
    amsi_benign)
        feed_stream "datasets/windows_amsi_benign.json" "shared-logs/windows_sysmon.json"
        ;;
    ad)
        feed_stream "datasets/ad_kerberoasting_dcsync.json" "shared-logs/windows_sysmon.json"
        ;;
    jwt)
        feed_stream "datasets/web_jwt_sqli.log" "shared-logs/web_access.log"
        ;;
    all)
        feed_stream "datasets/docker_escape.log" "shared-logs/linux_auth.log"
        feed_stream "datasets/windows_amsi_bypass.json" "shared-logs/windows_sysmon.json"
        feed_stream "datasets/windows_amsi_benign.json" "shared-logs/windows_sysmon.json"
        feed_stream "datasets/ad_kerberoasting_dcsync.json" "shared-logs/windows_sysmon.json"
        feed_stream "datasets/web_jwt_sqli.log" "shared-logs/web_access.log"
        ;;
    *)
        echo "Usage: $0 {docker|docker_live|amsi|amsi_benign|ad|jwt|all} [delay_seconds]"
        exit 1
        ;;
esac
