FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY . .

RUN go mod download
RUN go build -o server .

FROM alpine:latest

RUN apk add --no-cache libc6-compat

COPY --from=builder /app/server /server
COPY --from=builder /app/public /public
COPY --from=builder /app/superkeys.txt /superkeys.txt

EXPOSE 8080

CMD ["/server"]
