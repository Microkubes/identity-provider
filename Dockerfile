### Multi-stage build
FROM golang:1.10-alpine3.7 as build

RUN apk --no-cache add git curl openssh

RUN go get -u -v github.com/goadesign/goa/... && \
    go get -u -v github.com/crewjam/saml && \
    go get -u -v github.com/zenazn/goji/web && \
    go get -u -v github.com/Microkubes/microservice-security/... && \
    go get -u -v github.com/Microkubes/microservice-tools/...

COPY . /go/src/github.com/Microkubes/identity-provider

#RUN go install github.com/Microkubes/identity-provider
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install github.com/Microkubes/identity-provider

### Main
FROM scratch

ENV API_GATEWAY_URL="http://localhost:8001"

COPY --from=build /go/bin/identity-provider /identity-provider
COPY --from=build /go/src/github.com/Microkubes/identity-provider/config.json /run/secrets/microservice_identity_provider_config.json
COPY public /public

EXPOSE 8080
CMD ["/identity-provider"]
