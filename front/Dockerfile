
FROM golang:1.22-alpine

RUN apk update && apk add --no-cache gcc musl-dev

WORKDIR /app


COPY go.mod go.sum ./

RUN go mod download

COPY . .


RUN go build -o /front


EXPOSE 8080


CMD ["/front"]

