FROM ubuntu:18.04

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev

RUN apt install -y git

RUN mkdir /test_task

WORKDIR /test_task

#Copy project repository files
COPY . .

RUN ./configure --enable-debug && make -j8 && make install

RUN export PATH=/usr/local/zeek/bin:$PATH



ENTRYPOINT ["/bin/bash"]


