# syntax=docker/dockerfile:1

FROM golang:1.16-alpine

WORKDIR $GOPATH/github.com/andreacv98/weatheroas-reverseproxy

# Download necessary Go modules
COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY ./src ./src

RUN go build ./... -o /weatheroas-reverseproxy

EXPOSE 2957

CMD [ "/weatheroas-reverseproxy" ]

