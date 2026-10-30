#!/bin/bash

TYPE=$1
DELAY=${2:-0.05}

feed_stream() {
    SRC=$1
    DST=$2
    if [ -f "$SRC" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            echo "$line" >> "$DST"
            sleep "$DELAY"
        done < "$SRC"
    fi
}

case "$TYPE" in
    web)
        feed_stream "datasets/owasp_sqli.log" "shared-logs/web_access.log"
        ;;
    ssh)
        feed_stream "datasets/openssh_bruteforce.log" "shared-logs/linux_auth.log"
        ;;
    sysmon)
        feed_stream "datasets/windows_sysmon_execution.json" "shared-logs/windows_sysmon.json"
        ;;
    benign)
        feed_stream "datasets/windows_sysmon_benign.json" "shared-logs/windows_sysmon.json"
        ;;
    all)
        feed_stream "datasets/owasp_sqli.log" "shared-logs/web_access.log"
        feed_stream "datasets/openssh_bruteforce.log" "shared-logs/linux_auth.log"
        feed_stream "datasets/windows_sysmon_execution.json" "shared-logs/windows_sysmon.json"
        feed_stream "datasets/windows_sysmon_benign.json" "shared-logs/windows_sysmon.json"
        ;;
    *)
        echo "Usage: $0 {web|ssh|sysmon|benign|all} [delay_seconds]"
        exit 1
        ;;
esac
