FROM ubuntu:20.04 AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y git golang && apt-get clean
RUN mkdir -p /root/dist && \
    cd /root && git clone https://github.com/kentik/pkg.git && \
    cd pkg && go build . && mv pkg /usr/bin/pkg

FROM base as builder
ENV VERSION=1.0.0
COPY package.sh /root
CMD /root/package.sh
