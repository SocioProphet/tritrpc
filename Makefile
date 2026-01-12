.PHONY: verify fmt rust-fmt go-fmt rust-test go-test fixtures

verify: fmt rust-test go-test fixtures

fmt: rust-fmt go-fmt

rust-fmt:
	cd rust/tritrpc_v1 && cargo fmt --check

go-fmt:
	cd go/tritrpcv1 && test -z "$$(gofmt -l .)"

rust-test:
	cd rust/tritrpc_v1 && cargo test

go-test:
	cd go/tritrpcv1 && go test

fixtures:
	python tools/verify_fixtures_strict.py
