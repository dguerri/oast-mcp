FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go test -c -tags smoke -o /smoke.test ./test/smoke/
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o /agent ./cmd/agent/

FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    dnsutils curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /smoke.test /usr/local/bin/smoke.test
COPY --from=builder /agent /usr/local/bin/agent
ENV AGENT_BINARY=/usr/local/bin/agent
ENTRYPOINT ["/usr/local/bin/smoke.test", "-test.v", "-test.timeout=120s"]
