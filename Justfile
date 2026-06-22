vendor:
	cargo vendor && tar -czvf vendor.tar.gz vendor
	cargo package --no-verify && cp target/package/*.crate subid_dyn.crate