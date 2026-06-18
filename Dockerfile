# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src

# Telecharge les dependances en premier pour profiter du cache de couche
COPY go.mod go.sum ./
RUN go mod download

# Compile le code local du projet
COPY . .
ARG GIT_COMMIT=docker
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X main.GitCommit=${GIT_COMMIT}" \
      -o /ton-proxy ./cmd/proxy-cli


FROM alpine:3.22

RUN apk add --no-cache bash curl ca-certificates

COPY --from=build /ton-proxy /usr/local/bin/ton-proxy

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ton-proxy"]
CMD ["-addr", "0.0.0.0:8080"]
