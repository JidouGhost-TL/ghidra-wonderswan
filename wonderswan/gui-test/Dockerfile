# Headed GUI smoke-test image: JDK 21 + Xvfb. Ghidra and the repo are mounted
# at run time, not baked in, so the test always runs against the current tree
# and the host's Ghidra install.
# Build:  docker build -t ghidra-ws-guitest wonderswan/gui-test
# Run:    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/work/build/gui-home \
#           -v /opt/ghidra_12.1.3_PUBLIC:/opt/ghidra_12.1.3_PUBLIC:ro \
#           -v "$PWD":/work ghidra-ws-guitest
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qy && apt-get install -qy --no-install-recommends \
      ca-certificates openjdk-21-jdk xvfb unzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ENTRYPOINT ["./wonderswan/gui-test/run.sh"]
