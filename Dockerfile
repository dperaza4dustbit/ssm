FROM	registry.access.redhat.com/ubi8/ubi
SHELL	["/bin/bash", "-euvxo", "pipefail", "-c"]
USER	root
RUN	yum clean all; \
	yum upgrade -y --setopt=tsflags=nodocs; \
	groupadd --gid 2000 --system davp; \
	useradd -m -d /opt/ssm --system -s /sbin/nologin --uid 1000 -g davp davp; \
	chmod -vR 740 /opt/ssm; \
	chown -vR davp:davp /opt/ssm

WORKDIR	/opt/ssm
USER davp
COPY ssm ./ssm
EXPOSE  8080
ENTRYPOINT ["./ssm"]
