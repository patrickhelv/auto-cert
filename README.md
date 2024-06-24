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
VAULT_PATH = /mnt/ansible-vault/
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

We know create the configcerts.ini file

```bash
[nano or nvim] configcerts.ini
```


This is an example configcerts.ini file

```ini
[NAME OF HOST]
server_cert_name: {INSERT NAME OF FILE HERE}
server_key_name:{INSERT NAME OF KEY FILE HERE}
server_cn: {INSERT NAME OF SERVER DNS COMMON NAME HERE}
server_san: {INSERT NAME OF SERVER DNS SUBJECTIVE ALTERNATIVE NAME HERE}
client_cert_name: {INSERT NAME OF FILE HERE}
client_key_name:{INSERT NAME OF KEY FILE HERE}
client_cn: {INSERT NAME OF SERVER DNS COMMON NAME HERE}
client_san: {INSERT NAME OF SERVER DNS SUBJECTIVE ALTERNATIVE NAME HERE}

[NAME OF HOST 2]
server_cert_name: {INSERT NAME OF FILE HERE}
server_key_name:{INSERT NAME OF KEY FILE HERE}
server_cn: {INSERT NAME OF SERVER DNS COMMON NAME HERE}
server_san: {INSERT NAME OF SERVER DNS SUBJECTIVE ALTERNATIVE NAME HERE}
client_cert_name: {INSERT NAME OF FILE HERE}
client_key_name:{INSERT NAME OF KEY FILE HERE}
client_cn: {INSERT NAME OF SERVER DNS COMMON NAME HERE}
client_san: {INSERT NAME OF SERVER DNS SUBJECTIVE ALTERNATIVE NAME HERE}

....

[token]
NAME: {INSERT NAME OF TOKEN FILE HERE}
KEYNAME: {INSERT NAME OF TOKEN KEY FILE HERE}
NAME: {INSERT NAME OF TOKEN FILE HERE}
KEYNAME: {INSERT NAME OF TOKEN KEY FILE HERE}
```

a template like this for 3 nodes, in a cluster

```ini
[host1]
server_cert_name: server_cert_ctrl
server_key_name: server_key_ctrl
server_cn: host1.local
server_san: host1.local
client_cert_name: client_cert_ctrl
client_key_name: client_key_ctrl
client_cn: host1.local
client_san: host1.local

[host2]
server_cert_name: server_cert_shim_1
server_key_name: server_key_shim_1
server_cn: host2.local
server_san: host2.local
client_cert_name: client_cert_shim_1
client_key_name: client_key_shim_1
client_cn: host2.local
client_san: host2.local

[host3]
server_cert_name: server_cert_shim_2
server_key_name: server_key_shim_2
server_cn: host3.local
server_san: host3.local
client_cert_name: client_cert_shim_2
client_key_name: client_key_shim_2
client_cn: host3.local
client_san: host3.local

[token]
NAME: token_ctrl
KEYNAME: token_key_ctrl
NAME: token_shim
KEYNAME: token_key_shim
```

Look at the diagram to better understand the controller/shim authentication [here](/docs/authentication.excalidraw.png)

### Running the auto deploy using ansible playbooks

Before activating and running automatically the playbooks you need to modify some options

Move over to the inventory folder
```bash
cd inventory
```

The k3s-agents are all the ros2 shims nodes you have in your cluster. You need to generate ssh key pairs for every
node in your cluster. Rename the file from k3s-agents-example to k3s-agents.ini.

```bash
nano/vi k3s-agents-example.ini
```

To generate a new keypair of ssh keys

```bash
ssh-keygen -t ecdsa -b 521 -f ~/.ssh/id_ecdsa_#
```

Copy your public ssh keys over to your nodes

```bash
ssh-copy-id -i ~/.ssh/id_ecdsa_#.pub user@ip-node-1
ssh-copy-id -i ~/.ssh/id_ecdsa_#.pub user@ip-node-2
```

You need to specify the ip ``(ip-node-1)`` for each node and the user login for each node ``(ansible_user=user)``. You keep your private keys and use add them to the ini file.

```ini
[k3s_agents]
ip-node-1 ansible_user=user ansible_ssh_private_key_file=~/.ssh/id_ecdsa ansible_connection=ssh
ip-node-2 ansible_user=user ansible_ssh_private_key_file=~/.ssh/id_ecdsa ansible_connection=ssh

[host1]
ip-node-1 ansible_user=user ansible_ssh_private_key_file=~/.ssh/id_ecdsa_1 ansible_connection=ssh

[host2]
ip-node-2 ansible_user=user ansible_ssh_private_key_file=~/.ssh/id_ecdsa_2 ansible_connection=ssh
```

You should now be good to go and activate the ``PLAYBOOK_OPTION`` in the configfile.txt.

### Docker

You need to change this line ``ENV CUSTOM_HOME=`` and add your homepath on your nodes in your cluster.
```
nano dockerfile
```

```bash
docker-compose up --build
```
or

```bash
docker-compose build
docker-compose up
```

### How to run on kubernetes in a cluster


see guide on how to make your own local registry [here](/Create%20local%20container%20registry.md).

How to push to local registry
```
docker build -t <image_name> .
docker tag my-image localhost:5001/my-image:tag
docker push localhost:5001/my-image:tag
```

You need to change your persistant-volume to your homepath
```
cd charts/
nano persistant-volume.yaml
```

Change the ``HOMEPATH`` to you actual home path in your system found on ~/.

```yaml
  hostPath:
    path: HOMEPATH/ansible-vault
    type: DirectoryOrCreate
```

```bash
kubectl apply -f persistant-volume.yaml
kubectl apply -f volume-claim.yaml
```

Now we need to deploy the different resources

```bash
cd /charts
nano deployment.yaml
```

Then you need to configure your core-dns chart 

```bash
nano core-dns.yaml 
```
Then you need to change some values in the yaml file, change ``IP`` to the real 
ip address you are using in your cluster.

```yaml
        hosts {
            IP host1.local
            IP host2.local
            IP host3.local
            fallthrough
        }
```

you need to modify the ssh-volume, change the ``HOMEPATH`` to your actual home path.
```yaml
      - name: ssh-volume
        hostPath:
          path: HOMEPATH/.ssh
          type: DirectoryOrCreate
```

```bash
kubectl apply -f deployment.yaml
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

