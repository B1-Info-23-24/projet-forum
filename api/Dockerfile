
FROM golang:1.22-alpine


RUN apk update && apk add --no-cache gcc musl-dev


WORKDIR /api


COPY go.mod go.sum ./


RUN go mod download


COPY . .


RUN go build -o go-api


RUN chmod +x go-api


EXPOSE 8181


CMD ["./go-api"]


