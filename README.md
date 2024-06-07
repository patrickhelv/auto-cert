# Auto-cert

## Description

Auto cert is an application that automatically creates a CA, a client cert and a client key, encrypts it using ansible-vault and stores the encrypted files on the host system (~/ansible-vault/). It also generates a JWT token that is used to authentication purposes. The token is also encrypted and stored in the ansible-vault. 


## Requirements

- go 1.22.1 (https://go.dev/doc/install)
- docker v26.0.0 (https://docs.docker.com/engine/install/)
- k3s v1.28.5 (or other kubernetes distribution) (https://k3s.io/)
- ansible 2.14 (https://docs.ansible.com/ansible/latest/installation_guide/installation_distros.html#installing-distros)

## Getting started

### Create your ansible-vault

You need to create your ansible-vault after you have installed ansible

```bash
mkdir -p ~/ansible-vault
ansible-vault create ~/ansible-vault/secrets.yml
```
Then you will be prompted with a password.

### Create your config folder

You need to create a config folder

```bash
mkdir config
cd config
```

Then we need to create 3 files configfile.txt and password.txt (that holds the vault password) and configcerts.ini

```bash
[nano or nvim] configfile.txt
```

```txt
VAULT_PATH = /mnt/
VAULT_PASS = /root/config/password.txt
PLAYBOOK_OPTION = bool (OPTIONAL) 
```

```bash
[nano or nvim] password.txt
```

write your password in this file of course without brackets

```txt
[YOUR ansible-vault PASSWORD] 
```

This is an example configcerts.ini file

```ini
[clientcert]
NAME: {INSERT NAME OF FILE HERE}
KEYNAME:{INSERT NAME OF KEY FILE HERE}
...
NAME: {INSERT NAME OF FILE HERE}
KEYNAME: {INSERT NAME OF KEY FILE HERE}

[servercert]
NAME: {INSERT NAME OF FILE HERE}
KEYNAME: {INSERT NAME OF KEY FILE HERE}
...
NAME: {INSERT NAME OF FILE HERE}
KEYNAME: {INSERT NAME OF KEY FILE HERE}

[token]
NAME: {INSERT NAME OF FILE HERE}
KEYNAME: {INSERT NAME OF KEY FILE HERE}
...
NAME: {INSERT NAME OF FILE HERE}
KEYNAME: {INSERT NAME OF KEY FILE HERE}
```

### Running the auto deploy using ansible playbooks

Before activating and running automatically the playbooks you need to modify some options

Move over to the inventory folder
```bash
cd inventory
```

Replace all the ``ip-node-1`` and ``ip-node-2`` references with the ip addresses of the nodes you want
your playbooks to execute on. 

```ini
[k3s_agents]
ip-node-1 ansible_user=user ansible_ssh_private_key_file=~/.ssh/id_ecdsa ansible_connection=ssh
ip-node-2 ansible_user=user ansible_ssh_private_key_file=~/.ssh/id_ecdsa ansible_connection=ssh

[shim_1]
ip-node-1 ansible_user=user ansible_ssh_private_key_file=~/.ssh/id_ecdsa ansible_connection=ssh

[shim_2]
ip-node-2 ansible_user=user ansible_ssh_private_key_file=~/.ssh/id_ecdsa ansible_connection=ssh
```

You should now be good to go and activate the ``PLAYBOOK_OPTION`` in the configfile.txt.

### Docker

```bash
docker-compose up --build
```
or

```bash
docker-compose build
docker-compose up
```

### How to run on kubernetes on a single node


see guide on how to make your own local registry [here](/Create%20local%20container%20registry.md).

How to push to local registry
```
docker build -t <image_name> .
docker tag my-image localhost:5001/my-image:tag
docker push localhost:5001/my-image:tag
```

```bash
cd /charts
kubectl apply -f deployment.yaml
```

### How to run on kubernetes in a cluster

```bash
cd /charts
kubectl apply -f persistant-volume.yaml
kubectl apply -f volume-claim.yaml
kubectl apply -f deploymentMultiNode.yaml
```

### How to deploy secrets.yaml

```bash
base64 -w 0 config/configcerts.ini
base64 -w 0 config/password.txt
```

Move over to charts

```bash
cd charts
```

Replace the fields in ``secrets-kctl.yaml``, ``config.ini: <base64-encoded-configcerts.ini>`` and ``ANSIBLE_VAULT_PASSWORD: <base64-encoded-password.txt>``.

```bash
apiVersion: v1
kind: Secret
metadata:
  name: secrets
type: Opaque
data:
  config.ini: <base64-encoded-configcerts.ini>
  ANSIBLE_VAULT_PASSWORD: <base64-encoded-password.txt>
```

```
kubectl apply -f secrets-kctl.yaml
```

### How to run locally

```bash
git clone https://gitlab.stud.idi.ntnu.no/master-thesis-ros2-k3s/auto-cert.git
cd /auto-cert
```

```bash
go mod download
go mod tidy
go run main.go
```

