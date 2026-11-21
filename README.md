# ansible-playbooks

Ansible playbooks for Sentinel NSM Kubernetes cluster bootstrap and infrastructure automation.

## Requirements

- Ansible 2.15+
- SSH key-based authentication
- Python 3.x on managed nodes
- RHEL 10 on all cluster nodes

## Structure

    ansible-playbooks/
    ├── ansible.cfg
    ├── inventory.ini
    ├── agent
    ├── files/
    ├── helm/
    ├── manifests/
    ├── playbooks/
    └── *.yml

## Inventory Groups

| Group | Hosts | Purpose |
|---|---|---|
| k8s_nodes | rhel-node1/2/3 | Control plane nodes |
| k8s_workers | rhel-worker1/2 | Worker nodes |
| k8s_storage | rhel-storage | NFS storage node |

## Bootstrap Playbooks

| Playbook | Description |
|---|---|
| initial-config.yml | Base OS configuration for all nodes |
| k8s-prereqs.yml | Kubernetes prerequisites (firewall ports) |
| k8s-install.yml | Install containerd, kubeadm, kubelet, kubectl |
| kubeadm-init.yml | Initialize control plane via kubeadm |
| kubeadm-join-control.yml | Join additional control plane nodes |
| haproxy.yml | HAProxy load balancer setup |
| keepalived.yml | Keepalived VIP for API server HA |
| nfs-server.yml | NFS server setup on storage node |
| cilium.yml | Cilium CNI installation |
| docker-repo-fix.yml | Fix Docker repo for RHEL |
| qemu-guest-agent.yml | QEMU guest agent for Proxmox |

## Helm Deployment Playbooks

| Playbook | Description |
|---|---|
| helm-install.yml | Install Helm |
| helm-vault.yml | Deploy HashiCorp Vault HA |
| helm-prometheus.yml | Deploy kube-prometheus-stack |
| helm-nfs.yml | Deploy NFS provisioner |
| helm-lemp.yml | Deploy LEMP stack |
| helm-lemp-site.yml | Deploy LEMP site config |

## Operational Playbooks

| Playbook | Description |
|---|---|
| playbooks/etcd-backup.yml | etcd snapshot backup to Proxmox |
| playbooks/etcd-metrics.yml | Expose etcd metrics for Prometheus |
| playbooks/vault-unseal.yml | Unseal Vault after restart |
| playbooks/cluster-health.yml | Cluster health checks |
| playbooks/patch_management.yml | OS patching with reboot handling |

## Usage

    # Bootstrap a new cluster
    ansible-playbook initial-config.yml -i inventory.ini -K
    ansible-playbook k8s-prereqs.yml -i inventory.ini -K
    ansible-playbook k8s-install.yml -i inventory.ini -K
    ansible-playbook kubeadm-init.yml -i inventory.ini -K

    # Operational tasks
    ansible-playbook playbooks/etcd-backup.yml -i inventory.ini -K
    ansible-playbook playbooks/vault-unseal.yml -i inventory.ini -K

## Notes

- inventory.ini contains internal cluster IPs — update for your environment
- vault-keys.yml is Ansible Vault encrypted — safe to commit
- helm-lemp.yml contains placeholder passwords — update before running
- etcd backups stored on Proxmox at /mnt/backup/etcd, 7-day retention
