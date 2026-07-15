# BUILD STEPS — MSc Dissertation Detection Lab (Full Procedure)

**Student:** Abdul Basit Mohammed | Sheffield Hallam University
**Project:** Detection Engineering with Intelligent Alert Triage — a MITRE ATT&CK-mapped detection pipeline with ML-based alert prioritisation.

This document is the **reproducible, step-by-step build record** for the purple-team lab. It is written so the entire environment can be rebuilt from nothing, and so the methodology is fully traceable for the dissertation. Commands are given as they were actually run. Passwords are never recorded here — where a password is set, it is noted as "(set, not recorded)".

Companion file: `BUILD_LOG.md` (higher-level narrative + incident log).

---

## 0. Overview & design decisions

**Goal:** three VMs forming a purple-team loop — emulate ATT&CK techniques on a Windows endpoint, capture telemetry, detect with a SIEM, and (later) add ML-based alert triage.

| Role | VM | OS | Purpose | labnet IP |
|------|----|----|---------|-----------|
| Red | Kali | Kali Linux (official image) | CALDERA C2 + attack tooling | 10.10.10.30 |
| Blue | BlueTeam_Wazuh_VM | Ubuntu Server 25.04 | Wazuh SIEM | 10.10.10.10 |
| Endpoint | Endpoint_Windows10_VM | Windows 10 Pro | Victim/sensor | 10.10.10.20 |

**Host:** Lenovo laptop, Windows 11 Home, 16 GB RAM.

**Hypervisor decision:** VMware Workstation was attempted first but conflicted with the host's Windows 11 Hyper-V / VBS / Credential Guard security stack (persistent clock-rate errors). VirtualBox was adopted instead, with host security left enabled — VirtualBox tolerates Hyper-V mode (runs slightly slower, shows a green turtle icon; this is expected, not an error).

**Networking model — each VM has two adapters:**
- Adapter 1 = NAT (internet, for package downloads/updates)
- Adapter 2 = Internal Network named `labnet` (isolated VM-to-VM network where attacks happen safely)
- Blue additionally gets Adapter 3 = Host-Only (`vboxnet0`, 192.168.56.0/24) for host management (SSH + browser access to the dashboard)

**Static IP scheme (on labnet):** Blue 10.10.10.10, Windows 10.10.10.20, Kali 10.10.10.30.

---

## 1. Version control (do this first)

A private GitHub repo tracks all documentation and artefacts. Rule: commit after each meaningful milestone; never commit passwords.

```
# On the host, in the repo folder:
git pull                 # always pull before pushing
git add .
git commit -m "message"
git push
```

Repo: `dissertation-detection-lab` (private). Files: README.md, BUILD_LOG.md, BUILD_STEPS.md, and later Sigma rules, CALDERA profiles, ATT&CK Navigator layers, ML notebooks.

---

## 2. VirtualBox base setup

1. Install VirtualBox + the Extension Pack (host security features left ON).
2. Create the internal network implicitly by naming Adapter 2 `labnet` on each VM (VirtualBox creates it automatically).
3. For host access to Blue, create a Host-Only network: **Tools → Network Manager → Host-only Networks → Create** (default `vboxnet0`, 192.168.56.1/24, DHCP enabled).

---

## 3. Build the Kali VM (Red)

1. Download the official pre-built Kali VirtualBox image from kali.org.
2. Import via **Machine → Open** → select the extracted `.vbox` file. (This VirtualBox version uses "Open", not "Add".)
3. Resources: 3023 MB RAM, 2 CPUs (as shipped).
4. Add Adapter 2 → Internal Network → name `labnet`.
5. Default login `kali` / `kali`.
6. Assign static IP on the labnet interface (verify the interface name with `ip a` first — it may not be `eth1`):
   ```
   sudo nmcli con add type ethernet ifname eth1 con-name labnet ip4 10.10.10.30/24
   sudo nmcli con up labnet
   ```

---

## 4. Build the Blue VM (Ubuntu Server — Wazuh host)

1. **Machine → New.** Attach the Ubuntu Server 25.04 ISO so VirtualBox auto-detects Linux/Ubuntu. Leave **"Proceed with Unattended Installation" UNticked** (the unattended wizard misbehaves — do a normal manual install).
2. Resources: 4096 MB RAM (later raised to 6144 MB), 2 CPUs, 50 GB disk.
3. During install: hostname `bluesiem`, user `basit` (password set, not recorded), **tick "Install OpenSSH server"**.
4. Add Adapter 2 → Internal Network → `labnet`.
5. Static IP via netplan — edit `/etc/netplan/50-cloud-init.yaml`:
   ```yaml
   network:
     version: 2
     ethernets:
       enp0s3:
         dhcp4: true
       enp0s8:
         dhcp4: no
         addresses: [10.10.10.10/24]
   ```
   Then `sudo netplan apply`. Fix the permissions warning with `sudo chmod 600 /etc/netplan/50-cloud-init.yaml`.
6. **Grow the disk partition to full size** (critical — see lessons). The virtual disk is 50 GB but the LVM only claimed ~24 GB:
   ```
   sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv
   sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
   df -h /        # confirm ~48 GB
   ```

### 4a. Host-Only adapter for SSH + dashboard access
1. Power Blue off. Add Adapter 3 → Host-only Adapter → `vboxnet0`.
2. Boot; confirm the new interface (e.g. `enp0s9`) got a `192.168.56.x` IP via DHCP (`ip a`). Blue = 192.168.56.101.
3. SSH from the host: `ssh basit@192.168.56.101` (gives full copy/paste — Ubuntu Server has no GUI clipboard).

---

## 5. Build the Windows 10 VM (Endpoint)

1. **Machine → New**, attach Windows 10 ISO, unattended install UNticked.
2. Install Windows 10 Pro → **"I don't have a product key"** (runs unactivated permanently — only a watermark, no expiry; chosen deliberately over the 90-day eval to avoid deadline risk). Choose **Custom: Install Windows only**. Create a **local account** (not a Microsoft account).
3. Resources: 3072 MB RAM, 2 CPUs, 50 GB disk.
4. Add Adapter 2 → Internal Network → `labnet`.
5. Static IP: **Control Panel → Network Connections → labnet adapter (Ethernet 2) → IPv4 properties** → IP 10.10.10.20, mask 255.255.255.0, gateway/DNS blank.

**Verify networking:** all three VMs should ping each other on the 10.10.10.x network before proceeding.

---

## 6. Install Wazuh on Blue (step-by-step method)

> The all-in-one assistant (`wazuh-install.sh -a`) repeatedly failed on this low-resource VM (rolled everything back on any single failure). The **step-by-step method** below installs each component independently and is the reliable route. All commands on Blue via SSH.

### 6.0 Preparation — raise the systemd start timeout
Heavy Java services can exceed systemd's default ~90 s start window on a slow VM:
```
sudo mkdir -p /etc/systemd/system.conf.d
printf '[Manager]\nDefaultTimeoutStartSec=600s\n' | sudo tee /etc/systemd/system.conf.d/timeout.conf
sudo systemctl daemon-reexec
```

### 6.1 Add the Wazuh repo
```
sudo apt-get install -y gnupg apt-transport-https
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
```

### 6.2 Generate certificates (single-node — all three roles on 10.10.10.10)
```
cd ~
curl -sO https://packages.wazuh.com/4.14/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.14/config.yml
```
Edit `config.yml` so indexer/server/dashboard all use IP `10.10.10.10`, then:
```
sudo bash ./wazuh-certs-tool.sh -A
sudo tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
sudo rm -rf ./wazuh-certificates
```

### 6.3 Install the indexer
```
sudo apt-get install -y wazuh-indexer
```
Deploy its certs:
```
sudo mkdir -p /etc/wazuh-indexer/certs
sudo tar -xf ~/wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./node-1.pem ./node-1-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
sudo mv -n /etc/wazuh-indexer/certs/node-1.pem /etc/wazuh-indexer/certs/indexer.pem
sudo mv -n /etc/wazuh-indexer/certs/node-1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
sudo chmod 500 /etc/wazuh-indexer/certs
sudo chmod 400 /etc/wazuh-indexer/certs/*
sudo chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
```
**Cap the JVM heap BEFORE first start** (prevents the startup timeout):
```
sudo sed -i 's/^-Xms.*/-Xms2g/; s/^-Xmx.*/-Xmx2g/' /etc/wazuh-indexer/jvm.options
```
Start and initialise security:
```
sudo systemctl daemon-reload
sudo systemctl enable wazuh-indexer
sudo systemctl start wazuh-indexer
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh
```
Verify:
```
curl -k -u admin:admin https://10.10.10.10:9200        # expect cluster JSON
curl -k -u admin:admin https://10.10.10.10:9200/_cluster/health?pretty   # expect green/yellow
```

### 6.4 Install the manager
```
sudo apt-get install -y wazuh-manager
sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```
(The "Setting up wazuh-manager" phase is slow on this VM — allow a few minutes.)

### 6.5 Install and configure filebeat
```
sudo apt-get install -y filebeat
sudo curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.14/tpl/wazuh/filebeat/filebeat.yml
sudo curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/extensions/elasticsearch/7.x/wazuh-template.json
sudo chmod go+r /etc/filebeat/wazuh-template.json
sudo curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | sudo tar -xvz -C /usr/share/filebeat/module
```
Deploy filebeat certs:
```
sudo mkdir -p /etc/filebeat/certs
sudo tar -xf ~/wazuh-certificates.tar -C /etc/filebeat/certs/ ./wazuh-1.pem ./wazuh-1-key.pem ./root-ca.pem
sudo mv -n /etc/filebeat/certs/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
sudo mv -n /etc/filebeat/certs/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
sudo chmod 500 /etc/filebeat/certs
sudo chmod 400 /etc/filebeat/certs/*
sudo chown -R root:root /etc/filebeat/certs
```
Add the indexer credentials to filebeat's keystore:
```
sudo filebeat keystore create
echo admin | sudo filebeat keystore add username --stdin --force
echo admin | sudo filebeat keystore add password --stdin --force
```
**Important:** edit `/etc/filebeat/filebeat.yml` and set the output host to **`10.10.10.10:9200`** (NOT `localhost`/`127.0.0.1`) so it matches the TLS certificate. Then:
```
sudo filebeat test output      # expect handshake ... OK, talk to server ... OK
sudo systemctl daemon-reload
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### 6.6 Install the dashboard
```
sudo apt-get install -y wazuh-dashboard
```
Deploy its certs:
```
sudo mkdir -p /etc/wazuh-dashboard/certs
sudo tar -xf ~/wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./dashboard.pem ./dashboard-key.pem ./root-ca.pem
sudo chmod 500 /etc/wazuh-dashboard/certs
sudo chmod 400 /etc/wazuh-dashboard/certs/*
sudo chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
```
Edit `/etc/wazuh-dashboard/opensearch_dashboards.yml`: set `opensearch.hosts: https://10.10.10.10:9200` (match the cert), confirm `server.host: 0.0.0.0`. Then:
```
sudo systemctl daemon-reload
sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard
```

### 6.7 Verify the SIEM
- Browser (host): `https://192.168.56.101` → accept self-signed cert → log in `admin` / `admin`.
- Confirm cluster health green and the `wazuh-alerts-*` index is populating:
  ```
  curl -k -u admin:admin https://10.10.10.10:9200/_cat/indices/wazuh-*?v
  ```

---

## 7. Instrument the Windows endpoint

### 7.1 Sysmon (with SwiftOnSecurity config)
Admin PowerShell:
```
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Sysmon.zip
Expand-Archive C:\Sysmon.zip -DestinationPath C:\Sysmon
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Sysmon\sysmonconfig.xml
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```
Verify: `Get-Service Sysmon64` (Running) and `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5`.

### 7.2 Atomic Red Team
Admin PowerShell:
```
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```
(Approve the NuGet provider prompt if it appears.)

### 7.3 Wazuh agent (points at the manager on 10.10.10.10)
Admin PowerShell:
```
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi -OutFile $env:tmp\wazuh-agent
msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='10.10.10.10' WAZUH_AGENT_NAME='win-endpoint'
```
**The MSI does not auto-enrol** — the service dies on start (error 1067, no key) until the agent registers. Enrol manually, then start:
```
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 10.10.10.10
NET START WazuhSvc
```
Confirm in the dashboard (Endpoints) that the agent shows **active**.

---

## 8. CALDERA on Kali (Red team C2)

> Use the **official MITRE source install (git clone)**, NOT the Kali apt package — the packaged build shipped broken default data (every API call returned HTTP 500, empty agent list).

Dependencies (Go, Node.js/npm) must be present:
```
sudo apt-get install -y golang-go nodejs npm
```
Install and run from source:
```
cd ~
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip3 install -r requirements.txt --break-system-packages
python3 server.py --insecure --build       # first run only; drop --build afterwards
```
Access at `http://localhost:8888` (login `red` / password from `~/caldera/conf/local.yml`).
**CALDERA is not a service — it must be started manually each session** (`cd ~/caldera && python3 server.py --insecure`).

### 8.1 Deploy the Sandcat agent to Windows
In CALDERA: **agents → Deploy an agent → Sandcat → windows**, and set `app.contact.http` to **`http://10.10.10.30:8888`** (Kali's labnet IP, NOT 0.0.0.0/localhost). Copy the generated PowerShell command and run it on the Windows VM in admin PowerShell.

**Defender note:** the Sandcat one-liner is flagged by Defender AMSI as malicious (it functionally is attacker behaviour). On this deliberate lab endpoint, Tamper Protection and Real-time Protection are disabled (Windows Security → Virus & threat protection → Manage settings) so emulated techniques execute and are caught by the detection pipeline rather than pre-empted by Defender. Windows re-enables real-time protection on reboot, so this must be re-disabled per session.

**Persistence note:** the Sandcat agent runs as a transient hidden process (`splunkd.exe`), not a service, so it does **not** survive a Windows reboot and must be redeployed when starting a red-team session.

---

## 9. First end-to-end detection test (Stage 5)

The milestone that proves the whole pipeline. Requires Blue + Windows running.

On **Blue**, watch the live alert feed:
```
sudo tail -f /var/ossec/logs/alerts/alerts.log
```
On **Windows**, run a safe discovery technique:
```
Invoke-AtomicTest T1087.001
```
If Sysmon/process-creation events for the Windows agent appear in Blue's alert log, the full chain works: **attack → Sysmon → Wazuh agent → SIEM → alert.** This is the core dissertation infrastructure proven functional.

---

## 10. Snapshots & backup discipline

Once the lab is verified working, take a VirtualBox snapshot of each VM (do it **powered off** for the cleanest capture):
- Blue → `Blue-Wazuh-operational-<date>`
- Windows → `Windows-Sysmon-Atomic-WazuhAgent-Sandcat-<date>`
- Kali → `Kali-CALDERA-operational-<date>`

**Host disk warning:** snapshots of large VMs need several GB of free space on the host drive. Keep the host well above ~20 GB free — a full host disk can detach a VM's virtual disk (see incident in BUILD_LOG.md).

---

## 11. Remaining research phase (not yet started)

1. Write Sigma detection rules → convert to Wazuh local rules.
2. Run atomics across multiple ATT&CK techniques → build an ATT&CK Navigator coverage heatmap.
3. Export Wazuh alerts → build an ML prioritisation model in Python (scikit-learn, Random Forest / XGBoost) using ATT&CK tactic, affected asset, and rule confidence as features, with self-generated ground-truth labels.
4. Evaluate precision, recall, F1, false-positive rate; compare the full pipeline vs detection-engineering alone.
5. Install CALDERA adversary profiles for automated multi-step attack chains.
