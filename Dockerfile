# golang alpine
FROM golang:1.26.4-alpine AS builder

ARG TARGETARCH
ARG TARGETOS

ENV GO111MODULE=on
ENV GOPATH=/

RUN mkdir /opt/go-didx509-toolkit && cd /opt/go-didx509-toolkit
COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-w -s" -o /opt/go-didx509-toolkit/didx509-toolkit

# alpine
FROM alpine:3.21.2
RUN apk update \
  && apk add --no-cache \
             tzdata
COPY --from=builder /opt/go-didx509-toolkit/didx509-toolkit /usr/bin/didx509-toolkit

# set container user to non-root
#RUN adduser -D -H -u 18081 didx509-toolkit-usr
#USER 18081:18081

ENTRYPOINT ["/usr/bin/didx509-toolkit"]
CMD ["--help"]


