# Build PlatON in a stock Go builder container
FROM golang:1.16-alpine3.13 as builder

RUN apk add --no-cache make gcc musl-dev linux-headers g++ llvm bash cmake git gmp-dev openssl-dev

ADD . /appchain
RUN cd /appchain && make clean && make appchain

# Pull AppChain into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates libstdc++ bash tzdata gmp-dev
COPY --from=builder /AppChain-Go/build/bin/appchain /usr/local/bin/

VOLUME /data/appchain
EXPOSE 6060 6789 6790 6791 16789 16789/udp
CMD ["appchain"]