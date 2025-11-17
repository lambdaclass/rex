.PHONY: cli

cli: update-ethrex
	cargo install --path cli --locked

update-ethrex:
	cargo update \
	-p ethrex-common \
	-p ethrex-blockchain \
	-p ethrex-rlp \
	-p ethrex-rpc \
	-p ethrex-l2-rpc \
	-p ethrex-sdk \
	-p ethrex-l2-common
