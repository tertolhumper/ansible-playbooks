# Maintenance Playbooks

These playbooks are for ongoing maintenance of the Kubernetes cluster and Sentinel NSM infrastructure.
They are safe to run at any time unless noted otherwise.

---

## How to Run a Playbook

```bash
cd ~/ansible-proxmox
ansible-playbook playbooks/<playbook-name>.yml
```

Some playbooks require a sudo password. Add `-K` when prompted:
```bash
ansible-playbook playbooks/<playbook-name>.yml -K
```

---

## Playbooks

### cluster-health.yml
**What it does:** Checks the overall health of the entire cluster in one shot.
**When to run:** Daily, or whenever something feels off.
**Requires -K:** No

Checks:
- All nodes are Ready
- All pods are Running (fails if any pod is Pending, CrashLoopBackOff, or Error)
- All PVCs are Bound
- Vault is unsealed
- sentinel-nsm.com is reachable
- LEMP NodePort (nginx) is responding
- Grafana is responding
- Node CPU and memory usage

```bash
ansible-playbook playbooks/cluster-health.yml
```

---

### vault-unseal.yml
**What it does:** Unseals all 3 Vault pods after a restart or reboot.
**When to run:** After any reboot or when Vault pods show 0/1 Ready.
**Requires -K:** No
**Requires:** ANSIBLE_VAULT_PASSWORD_FILE set in ~/.bashrc

Vault seals itself every time the pod restarts. This playbook checks if Vault is sealed
and only runs the unseal commands if needed. Safe to run at any time.

```bash
ansible-playbook playbooks/vault-unseal.yml
```

---

### etcd-backup.yml
**What it does:** Takes a snapshot of the etcd database and saves it to /mnt/backup/etcd on Proxmox.
**When to run:** Before any major upgrade, or weekly as a scheduled backup.
**Requires -K:** Yes

etcd is the brain of Kubernetes. It stores the entire cluster state — all pods, services,
secrets, and configurations. If etcd is lost without a backup, the entire cluster must be
rebuilt from scratch. This playbook saves a snapshot to /mnt/backup/etcd with the date
in the filename. Only the last 7 snapshots are kept.

```bash
ansible-playbook playbooks/etcd-backup.yml -K
```

Backups are stored at:

/mnt/backup/etcd/etcd-snapshot-YYYY-MM-DD.db
