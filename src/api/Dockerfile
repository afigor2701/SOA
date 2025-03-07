FROM golang:1.21-alpine

WORKDIR /social_network/api

COPY go.* ./
RUN go mod download -x

COPY . .

RUN go build -o api

ENTRYPOINT ["./api"]
