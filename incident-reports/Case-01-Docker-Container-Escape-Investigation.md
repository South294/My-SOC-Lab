# INCIDENT INVESTIGATION REPORT: DOCKER CONTAINER ESCAPE (T1611)

## 1. Ticket Information
- Incident ID: INC-202611-001
- Priority: P1 - Critical
- Classification: True Positive
- Status: Closed / Remediated
- Assignee: SOC Tier 1 Analyst
- Target Host: Ubuntu 24.04 WSL2 Host (DESKTOP-O7NQ6VH)
- Detector: Wazuh Manager (Rule 100100)

## 2. Executive Summary (SBAR Framework)
- Situation: High-severity alert triggered indicating an execution of nsenter targeting PID 1 namespace from a privileged container session.
- Background: A microservice container was deployed with privileged flags, permitting access to the host pid namespace and IPC/UTS/Net namespaces.
- Assessment: Attacker successfully compromised the container and executed namespace switching commands to break out to the underlying host root shell.
- Recommendation: Revoke privileged container configurations, remove host namespace sharing, and enforce seccomp and AppArmor profiles.

## 3. Log Evidence & Analysis
Raw Log:
```text
Nov  9 09:16:02 DESKTOP-O7NQ6VH sudo:   nam2945 : TTY=pts/0 ; PWD=/home/nam2945/My-SOC-Lab ; USER=root ; COMMAND=/usr/bin/docker run --rm --privileged --pid=host alpine nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
```

Key Fields Extracted:
- Timestamp: Nov  9 09:16:02
- Hostname: DESKTOP-O7NQ6VH
- Program: sudo
- User: root
- Command: /usr/bin/docker run --rm --privileged --pid=host alpine nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
- Triggered Rule: 100100 (Level 13)

Analysis:
The command initiates a privileged container with `--pid=host` and executes `/usr/bin/nsenter` with `--target 1`. The parameter `--target 1` specifies switching to the namespace of process 1 (init / systemd). When executed with `--mount --uts --ipc --net --pid`, all container isolation boundaries are eliminated, yielding an interactive shell directly on the host operating system.

## 4. Threat Intelligence & Artifact Triage
- Command Executable: `/usr/bin/nsenter` (Standard Linux utility weaponized for container breakout)
- Source Environment: Docker Engine runtime on Ubuntu 24.04 LTS
- Internal Scope: Local execution; no external command and control IP observed in this initial phase.

## 5. MITRE ATT&CK Mapping
- Tactic: Privilege Escalation / Defense Evasion
- Technique ID: T1611 (Escape to Host)

## 6. Remediation & Containment Actions
- Containment: Immediately identified and terminated the rogue container instance via `docker stop` and `docker rm`.
- Eradication: Inspected host filesystem for persistent artifacts in `/etc/cron*`, `/root/.ssh/authorized_keys`, and `/tmp`.
- Recovery: Verified host system integrity and restored container services using restricted non-root manifests.

## 7. Lessons Learned & Rule Tuning
- Ensure Docker daemon startup parameter disables root socket exposure.
- Rule 100100 successfully identified the escape command. No suppression required as nsenter to target 1 is not permitted in production microservices.

