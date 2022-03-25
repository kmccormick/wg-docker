WORKDIR ?= /opt/wg-docker

include Makefile.venv

.DEFAULT_GOAL := install
install: venv $(WORKDIR)/wg-docker.py $(WORKDIR)/ca.crt $(WORKDIR)/credentials /etc/systemd/system/wg-docker.service

$(WORKDIR):
	install -d -o root -g root -m 0755 $@

$(WORKDIR)/wg-docker.py: wg-docker.py
	install -o root -g root -m 0755 $< $@
	sed -i "s|WORKDIR|$(WORKDIR)|g" $@

$(WORKDIR)/ca.crt: ca.crt
	install -o root -g root -m 0644 $< $@

$(WORKDIR)/credentials:
	install -o root -g root -m 0600 /dev/null $@

/etc/systemd/system/wg-docker.service: systemd.service
	install -o root -g root -m 0644 $< $@
	sed -i "s|WORKDIR|$(WORKDIR)|g" $@
	systemctl daemon-reload
