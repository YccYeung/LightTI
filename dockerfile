# Stage 1 — build: compile the binary inside a full Go image.
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Cross-compile for linux/amd64 to match the Cloud Run runtime.
RUN GOARCH=amd64 GOOS=linux go build -o lightti ./cmd/lightti

# Stage 2 — runtime: copy only the binary into a minimal alpine image to keep the image small.
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/lightti .
EXPOSE 8080
CMD [ "./lightti", "server"]