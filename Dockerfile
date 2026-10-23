FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /witness-watcher ./cmd/server
RUN CGO_ENABLED=0 go build -o /repair-sequences ./cmd/repair-sequences

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
ENV WW_DATA_DIR=/data
ENV PORT=8092
ENV HOST=0.0.0.0
VOLUME ["/data"]
COPY --from=build /witness-watcher /app/witness-watcher
COPY --from=build /repair-sequences /app/repair-sequences
EXPOSE 8092
HEALTHCHECK --interval=30s --timeout=5s \
  CMD wget -qO- http://127.0.0.1:8092/health || exit 1
CMD ["/app/witness-watcher"]