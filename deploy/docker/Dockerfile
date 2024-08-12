FROM golang:1.22.1 as build

WORKDIR /nodpi

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o /nodpi/server ./main/main.go

FROM alpine:3.14

WORKDIR /

COPY --from=build /nodpi/server server

EXPOSE 80

CMD [ "/server" "--config" "/config.json" ]