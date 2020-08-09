FROM golang:1.14 as builder

WORKDIR /src

COPY . .

RUN go build -o sso main.go

FROM golang:1.14 as app

COPY --from=builder /src/sso sso

ENTRYPOINT ["./sso"]
