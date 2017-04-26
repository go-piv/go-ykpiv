# $ docker build -t paultag/go-ykpiv .
# $ docker run -it --rm -v /run/pcscd/pcscd.comm:/run/pcscd/pcscd.comm paultag/go-ykpiv

FROM debian:stretch-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		gcc \
		git \
		golang-any \
		libc6-dev \
		libykpiv-dev \
		\
# this isn't strictly necessary, but it's a useful tool to have available
		yubico-piv-tool \
	&& rm -rf /var/lib/apt/lists/*

ENV GOPATH /go
WORKDIR $GOPATH/src/pault.ag/go/ykpiv
COPY . .

RUN go get -v -t ./...
