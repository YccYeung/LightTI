FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOARCH=amd64 GOOS=linux go build -o lightti ./cmd/lightti

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/lightti .
EXPOSE 8080
CMD [ "./lightti", "server"]