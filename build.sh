#!/bin/bash
set -e

go build -o ./quicgo-server ./cmd/server/main.go
go build -o ./quicgo-client ./cmd/client/main.go