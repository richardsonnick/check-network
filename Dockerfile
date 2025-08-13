FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build for cluster
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/check-network .

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

USER root

RUN microdnf install -y nmap tar && microdnf clean all

COPY --from=builder /app/check-network /usr/local/bin/check-network

USER 1001

CMD ["sleep", "infinity"]
