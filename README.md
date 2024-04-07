# Auto-cert

## Description

Auto cert is an application that automatically creates a CA, a client cert and a client key, encrypts it using ansible-vault and stores the encrypted files on the host system (~/ansible-vault/).


## Requirements

- go 1.22.1 (https://go.dev/doc/install)
- docker v26.0.0 (https://docs.docker.com/engine/install/)
- k3s v1.28.5 (or other kubernetes distribution) (https://k3s.io/)
- ansible 2.14 (https://docs.ansible.com/ansible/latest/installation_guide/installation_distros.html#installing-distros)

## Getting started

### Create your ansible-vault

You need to create your ansible-vault after you have installed ansible-vault

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

Then we need to create 2 files configfile.txt and password.txt

```bash
[nano or nvim] configfile.txt
```

```txt
VAULT_PATH = /mnt/
VAULT_PASS = /root/config/password.txt
```

```bash
[nano or nvim] password.txt
```

write your password in this file of course without brackets

```txt
[YOUR ansible-vault PASSWORD] 
```

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

