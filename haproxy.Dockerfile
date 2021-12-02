FROM	alpine:3.15.0
RUN	apk update; \
	apk add --no-cache bash
SHELL	["/bin/bash", "-xeo", "pipefail", "-c"]

ARG	HAPROXY="https://github.com/haproxy/haproxy.git,v2.3.0"

USER    root
RUN	addgroup -g 2000 -S davp; \
	adduser -h /opt/haproxy -D -S -s /sbin/nologin -u 1000 -G davp -g davp davp; \
	chmod -vR 740 /opt/haproxy; \
	chown -vR davp:davp /opt/haproxy

RUN	apk update; \
	apk add --virtual .deps --upgrade --no-cache alpine-sdk autoconf automake binutils build-base ca-certificates cmake coreutils curl file git gperf g++ libc-dev libmount libtool linux-headers make musl-dev openssl-dev openssl-libs-static pkgconfig zlib-dev zlib-static; \
	_vcs="$(cut -d',' -f1 <<<"${HAPROXY}")"; \
	_proj="$(basename "${_vcs}")"; \
	git clone --depth=1 \
		--recurse-submodules -j$(nproc) --shallow-submodules \
		--branch="$(cut -d',' -f2 <<<"${HAPROXY}")" \
		"${_vcs}" /usr/src/"${_proj%.*}"; \
	cd /usr/src/haproxy; \
	make -j$(nproc) TARGET=linux-musl USE_OPENSSL=1 LDFLAGS="-lc -lpthread -Wl,-rpath -Wl,-static -static -s" USE_GETADDRINFO=1 USE_NS=1 USE_REGPARM=1 USE_TFO=1 USE_THREAD=1 USE_ZLIB=1; \
	file haproxy; \
	strip haproxy; \
	du -sh haproxy; \
	mv haproxy /opt/haproxy; \
	cd ..; \
	rm -rf ./haproxy;

USER    davp
WORKDIR /opt/haproxy
