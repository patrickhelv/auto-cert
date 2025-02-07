FROM golang:1.22.1 as builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download \ 
go mod tidy

COPY /ca-gen /cert-gen /certificate /client-gen /token-gen /utility /vault main.go ./    

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o autocert .

FROM alpine:latest

RUN apk update && \
    apk add --no-cache ansible openssh

WORKDIR /root/

COPY --from=builder /app/autocert .

COPY config /root/config
COPY ansible.cfg /root/
COPY inventory /root/inventory
COPY playbooks /root/playbooks

ENTRYPOINT ["./autocert"]