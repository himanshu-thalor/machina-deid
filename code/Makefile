PYTHON ?= ../.venv/Scripts/python
WORKERS ?= 8

.PHONY: test sample run-sample audit-sample docker-build docker-smoke clean

test:
	PYTHONPATH=. $(PYTHON) -m pytest ../tests -v

sample:
	$(PYTHON) ../scripts/fetch_stratified_sample.py

run-sample:
	PYTHONPATH=. $(PYTHON) -m machina_deid run \
		--input ../sample_input \
		--output ../sample_output/corpus \
		--state-dir ../private_state \
		--workers $(WORKERS) \
		--readme-out ../README.txt

audit-sample:
	PYTHONPATH=. $(PYTHON) -m machina_deid audit \
		--corpus ../sample_output/corpus \
		--state-dir ../private_state

docker-build:
	docker build -t machina-deid .

docker-smoke:
	docker run --rm \
		-v "$(CURDIR)/../sample_input:/work/in:ro" \
		-v "$(CURDIR)/../sample_output_docker:/work/out" \
		-v "$(CURDIR)/../private_state_docker:/work/state" \
		machina-deid run --input /work/in --output /work/out/corpus --state-dir /work/state --workers 4 --no-ocr

clean:
	rm -rf ../sample_output ../private_state ../sample_output_docker ../private_state_docker
