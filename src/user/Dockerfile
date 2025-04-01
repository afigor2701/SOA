FROM golang:1.21-alpine

WORKDIR /social_network/user
COPY go.* ./

RUN go mod download -x

COPY . .

RUN go build -o user

RUN apk add --no-cache bash curl

ENTRYPOINT ["./user"]