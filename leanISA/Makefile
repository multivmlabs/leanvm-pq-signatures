PYTHON := .venv/bin/python
ARTICLE_SCHEMES ?= ethfalcon falcon ethdilithium mldsa fors
ARTICLE_ARGS ?=
ARTICLE_FIGURE_ARGS ?=
export PYTHONPATH := $(CURDIR)/python
export PYTHONPYCACHEPREFIX := $(CURDIR)/.cache/python

.PHONY: setup build smoke bench test baseline experiment-30 article-inputs article-bench article-plot-deps article-figures
setup:
	python3 scripts/bootstrap.py
	python3 -m venv .venv
	$(PYTHON) -m pip install -r requirements.lock.txt

build:
	cargo build --release --locked

smoke: build
	$(PYTHON) -m pqbench bench --schemes fors --counts 1 --repeat 1 --warmup 0 --out results/smoke

bench: build
	$(PYTHON) -m pqbench bench --schemes ethfalcon ethdilithium fors --counts 1 --repeat 3 --warmup 1

test: build
	cargo test --release --locked --bin aggregate-falcon
	cargo test --release --locked --bin aggregate-tree
	$(PYTHON) -m unittest discover -s tests -v

article-inputs: build
	@for scheme in $(ARTICLE_SCHEMES); do $(PYTHON) -m pqbench.article_inputs records --scheme $$scheme --count 100 || exit $$?; done

article-bench: build
	$(PYTHON) scripts/article_bench.py all --schemes $(ARTICLE_SCHEMES) $(ARTICLE_ARGS)

article-plot-deps:
	$(PYTHON) -m pip install -r requirements-plots.txt

article-figures: article-plot-deps
	$(PYTHON) scripts/article_figures.py $(ARTICLE_FIGURE_ARGS)

experiment-30: build
	$(PYTHON) -m pqbench.falcon_aggregate_inputs --out artifacts/falcon-30-recursive
	target/release/aggregate-falcon prove --manifest artifacts/falcon-30-recursive/public.json --leaf-source artifacts/falcon-30-recursive/leaf-program.py --leaf-dir artifacts/falcon-30-recursive/leaves --out-dir artifacts/falcon-30-recursive/proofs --expect-leaf-guest-hash 4b4502f2a1a4231617baba69b86e1e4470cff3c3815c66eb8fdcb6e2c2db8a2e

baseline:
	cargo run --release --locked --manifest-path vendor/leanVM/Cargo.toml -p leanvm-cli -- aggregate --sphincs 16 --repeat 3 --cooldown 0
