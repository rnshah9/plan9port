FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang

COPY . /repo
WORKDIR /repo
RUN ./INSTALL
RUN clang++ /repo/mayhem/fuzz_utflen.cpp -fsanitize=fuzzer,address -L /repo/lib/ -l9 -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /repo/bin/fmt /
COPY --from=builder /fuzz /fuzz_utflen