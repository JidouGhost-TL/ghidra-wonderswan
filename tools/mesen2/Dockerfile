# Mesen 2 (GPL-3.0, https://github.com/SourMesen/Mesen2) built for headless use as a reference
# oracle (execution traces, code/data logs, screenshots) via its --testRunner Lua mode.
# Used as an external tool only; no Mesen code is copied into the Ghidra extensions.
FROM ubuntu:24.04
ARG MESEN_COMMIT=b9fa69ddc6d0a331fb103fdb5eef6904305703c2
ENV DEBIAN_FRONTEND=noninteractive DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
RUN apt-get update -qy && apt-get install -qy --no-install-recommends \
      ca-certificates git make clang lld zip libsdl2-dev dotnet-sdk-8.0 libicu74 \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/SourMesen/Mesen2 /src/Mesen2 && cd /src/Mesen2 && git checkout -q "$MESEN_COMMIT"
WORKDIR /src/Mesen2
RUN make -j"$(nproc)" && find bin -name Mesen -type f -perm -u+x
RUN ln -s "$(find /src/Mesen2/bin -path '*publish/Mesen' -type f | head -1)" /usr/local/bin/Mesen
# Mesen keeps config/home in $HOME/.config/Mesen2. Without settings.json it opens its first-run
# wizard (a desktop UI) before checking --testRunner, so ship a minimal one. Lua file I/O is enabled
# so trace scripts can write their output files; the script timeout is raised from 1 s so the
# end-of-run CDL dump (a multi-megabyte pure-Lua CRC + flag loop) fits in one callback.
RUN useradd -m mesen && mkdir -p /home/mesen/.config/Mesen2 \
    && printf '{"Debug":{"ScriptWindow":{"AllowIoOsAccess":true,"ScriptTimeout":60}}}' > /home/mesen/.config/Mesen2/settings.json \
    && chown -R mesen:mesen /home/mesen
USER mesen
WORKDIR /work
ENTRYPOINT ["Mesen"]
