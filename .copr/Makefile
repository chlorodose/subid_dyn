srpm:
	dnf install -y just rpkg cargo tar gzip
	just vendor
	rpkg srpm --outdir . --spec subid-dyn.spec
	@if [ "$(abspath $(outdir))" != "$(abspath .)" ]; then \
		cp *.src.rpm $(outdir)/ ;\
	fi