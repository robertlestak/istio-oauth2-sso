FROM golang:1.21 as builder

WORKDIR /src

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o sso *.go

FROM golang:1.21 as app

COPY --from=builder /src/sso sso
COPY web web

ENTRYPOINT ["./sso"]
