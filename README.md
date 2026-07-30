# Ansible Playbooks

Production-ready Ansible playbooks for Linux infrastructure automation targeting Arch Linux and RHEL 10.

## Requirements
- Ansible 14.x
- SSH key-based authentication
- Python 3.x on managed nodes

## Structure

```
ansible-playbooks/
├── ansible.cfg
├── inventory.ini
├── templates/
│   └── sshd_config.j2
├── reports/
└── playbooks/
```

## Playbooks
| Playbook | Description | Targets |
|----------|-------------|---------|
| install_nginx.yml | Install and start nginx | All |
| remove_nginx.yml | Stop and remove nginx | All |
| config_management.yml | Deploy sshd_config via Jinja2 template | All |
| user_management.yml | Create sysadmin user and push SSH key | All |
| patch_management.yml | Update packages with reboot handling | All |
| rhel_hardening.yml | CIS-based security hardening | RHEL |
| compliance_report.yml | Generate compliance reports | All |
| app_deployment.yml | Deploy app with symlink rollback | All |
| cert_rotation.yml | Lets Encrypt certificate renewal | RHEL |
| disaster_recovery.yml | Backup and restore to dedicated drive | All |

## Usage
ansible-playbook --ask-become-pass <playbook>.yml
ansible-playbook --ask-become-pass <playbook>.yml --limit rhel

## Inventory
Configure hosts in inventory.ini
arch_vm ansible_host=192.168.x.x ansible_port=XXXX ansible_user=your_user ssh_port=XXXX
rhel_vm ansible_host=192.168.x.x ansible_port=XXXX ansible_user=your_user ssh_port=XXXX

## Notes
- inventory.ini contains internal IPs, update for your environment
- Disaster recovery requires /dev/sdb1 mounted at /mnt/backup
- cert_rotation.yml requires a public domain and DuckDNS token
- rhel_hardening.yml requires active RHEL subscription for nginx
