FROM golang:1.22-alpine3.19 AS stage1

WORKDIR /nodpi

RUN apk update
RUN apk add gcc musl-dev libpcap-dev

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ENV CGO_ENABLED=1
RUN go build -o ./v2ray-server ./main/

FROM alpine:3.19 AS stage2

WORKDIR /app

COPY --from=stage1 /nodpi/v2ray-server /app/v2ray-server

RUN apk update
RUN apk add gcc musl-dev libpcap-dev

CMD ["/app/v2ray-server", "run", "--config", "/config.json", "-format", "jsonv5"]