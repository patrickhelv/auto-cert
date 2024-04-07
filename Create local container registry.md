### Create an image

```bash
docker build -t <image_name> --rm
```

### start local registry

```
sudo docker run -d -p 5001:5000 --restart=always --name registry registry:latest
```

### Tag and push and image to your registry

```bash
docker tag my-image localhost:5001/my-image:tag
```

```bash
docker push localhost:5001/my-image:tag
```

### use local registry in k3s

```bash
cd /etc/rancher/k3s/
```

```bash
sudo nano registries.yaml
```

```yaml
mirrors:
  "localhost:5001":
    endpoint:
      - "http://localhost:5001"
```

Do this on every node in the cluster

```bash
sudo systemctl restart k3s
```

```bash
sudo systemctl restart k3s-agent
```


### Using TLS


```bash
docker run -d \
  -p 443:5000 \
  --restart=always \
  --name registry \
  -v $(pwd)/certs:/certs \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
  registry:latest
```

or use this file and mount it

```yaml
version: 0.1
log:
  fields:
    service: registry
storage:
    delete:
      enabled: true
http:
  addr: :5000
  tls:
    certificate: /certs/domain.crt
    key: /certs/domain.key
```


```bash
docker run -d \
  -p 443:5000 \
  --restart=always \
  --name registry \
  -v $(pwd)/certs:/certs \
  -v $(pwd)/config.yml:/etc/docker/registry/config.yml \
  registry:latest
```

- **For Certificates from a CA**: No extra steps are needed on client machines, as the CA is already trusted.
    
- **For Self-Signed Certificates**: You'll need to manually trust the self-signed certificate on each client that will access the registry.
    
    On **Linux**: Copy `domain.crt` to the `/etc/docker/certs.d/myregistrydomain.com:5001/ca.crt` on every Docker host. Replace `myregistrydomain.com:5001` with your registry's address.
    
    On **Windows** or **macOS**, you might need to add the certificate to your system's trusted certificates store.


#### In k3s

```bash
cd /etc/rancher/k3s/
```

```bash
sudo nano registries.yaml
```

For a Registry with a CA-signed Certificate
```yaml
mirrors:
  "myregistry.example.com":
    endpoint:
      - "https://myregistry.example.com"

```

Or if you're using a self-signed certificate, you'll also need to specify the path to the CA certificate on each k3s node so that k3s can trust your registry

```yaml
mirrors:
  "myregistry.example.com":
    endpoint:
      - "https://myregistry.example.com"
configs:
  "myregistry.example.com":
    tls:
      cert_file: /path/to/domain.crt
      key_file: /path/to/domain.key
      ca_file: /path/to/ca.crt

```


```bash
sudo systemctl restart k3s
```

```bash
sudo systemctl restart k3s-agent
```

