### Multi-stage build
FROM golang:1.13.5-alpine3.10 as build

RUN apk --no-cache add git curl openssh

COPY . /go/src/github.com/Microkubes/identity-provider

RUN cd /go/src/github.com/Microkubes/identity-provider && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install

### Main
FROM alpine:3.10

COPY --from=build /go/src/github.com/Microkubes/identity-provider/config.json /config.json
COPY --from=build /go/bin/identity-provider /identity-provider
COPY --from=build /etc/ssl/certs /etc/ssl/certs

COPY public /public

EXPOSE 8080

ENV API_GATEWAY_URL="http://localhost:8001"

CMD ["/identity-provider"]

