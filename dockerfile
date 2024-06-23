FROM golang:1.22.1 as builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download
RUN go mod tidy

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o autocert .

FROM alpine:latest

RUN apk update && \
    apk add --no-cache ansible openssh

WORKDIR /root/

ENV CUSTOM_HOME=

COPY --from=builder /app/autocert .
COPY config /root/config
COPY ansible.cfg /root/
COPY inventory /root/inventory
COPY playbooks /root/playbooks

CMD ["./autocert"]