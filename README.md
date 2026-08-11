# Ansible Playbooks

Ansible playbooks for Linux infrastructure automation targeting Arch Linux and RHEL 10.

## Requirements
- Ansible 14.x
- SSH key-based authentication
- Python 3.x on managed nodes

## Structure

```
ansible-playbooks/
├── ansible.cfg
├── inventory.ini
├── README.md
├── templates/
│   └── sshd_config.j2
├── reports/
└── kubernetes/
    ├── mongo.yaml
    ├── mongo-secret.yaml
    ├── mongo-config.yaml
    ├── webapp.yaml
    └── deploy-kubernetes-app.yml
```

## Playbooks
| Playbook | Description | Targets |
|----------|-------------|---------|
| install_nginx.yml | Install and start nginx | All |
| remove_nginx.yml | Stop and remove nginx | All |
| install_lemp.yml | Install LEMP stack (nginx + PHP + MariaDB) | All | 
| config_management.yml | Deploy sshd_config via Jinja2 template | All |
| user_management.yml | Create sysadmin user and push SSH key | All |
| patch_management.yml | Update packages with reboot handling | All |
| rhel_hardening.yml | CIS-based security hardening | RHEL |
| compliance_report.yml | Generate compliance reports | All |
| app_deployment.yml | Deploy app with symlink rollback | All |
| cert_rotation.yml | Lets Encrypt certificate renewal | RHEL |
| disaster_recovery.yml | Backup and restore to dedicated drive | All |
| kubernetes/deploy-kubernetes-app.yml | Deploy MongoDB + webapp to Kubernetes cluster | Ubuntu |

## Usage
```
ansible-playbook --ask-become-pass <playbook>.yml
ansible-playbook --ask-become-pass <playbook>.yml --limit rhel
```
## Inventory
Configure hosts in inventory.ini
```
arch_vm ansible_host=192.168.x.x ansible_port=XXXX ansible_user=your_user ssh_port=XXXX

rhel_vm ansible_host=192.168.x.x ansible_port=XXXX ansible_user=your_user ssh_port=XXXX
```
## Notes
- inventory.ini contains internal IPs, update for your environment
- Disaster recovery requires /dev/sdb1 mounted at /mnt/backup
- cert_rotation.yml requires a public domain and DuckDNS token
- rhel_hardening.yml requires active RHEL subscription for nginx

## Disaster Recovery Usage
```bash
# Backup only
ansible-playbook --ask-become-pass disaster_recovery.yml --tags backup

# Restore only
ansible-playbook --ask-become-pass disaster_recovery.yml --tags restore

# Target specific host
ansible-playbook --ask-become-pass disaster_recovery.yml --tags restore --limit rhel
```

## Disaster Recovery Notes
- Backup drive must be mounted at /mnt/backup before running
- Backups stored at /mnt/backup/<hostname>/<date>/
- Retention: 7 days, older backups purged automatically
- Tested: deleted /etc/nginx on RHEL, restored successfully from backup
- Backup includes: /etc, /home, /var/log, /var/www, /opt, /root

## Kubernetes Note
-  Run `sudo swapoff -a` on Ubuntu before executing the deploy playbook. 
