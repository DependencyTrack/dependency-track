# This file is part of Dependency-Track.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

MVN := $(shell command -v mvn 2>/dev/null)
MVND := $(shell command -v mvnd 2>/dev/null)
ifeq ($(MVND),)
	MVND := $(MVN)
endif

ifdef CI
	MVN_FLAGS := -B
else
	MVN_FLAGS :=
endif

ifdef AGENT
	MVN_FLAGS += -B -q -Dsurefire.useFile=false
endif

build:
	$(MVND) $(MVN_FLAGS) -q -Pquick package
.PHONY: build

build-dist:
	$(MVND) $(MVN_FLAGS) -q -Pdist,quick package
.PHONY: build-dist

build-image: build
	docker build \
		-t ghcr.io/dependencytrack/apiserver:local \
		-f apiserver/src/main/docker/Dockerfile \
		apiserver
.PHONY: build-image

build-v4-migrator-image: build
	docker build \
		-t ghcr.io/dependencytrack/v4-migrator:local \
		-f support/v4-migrator/src/main/docker/Dockerfile \
		support/v4-migrator
.PHONY: build-v4-migrator-image

datanucleus-enhance:
	$(MVND) $(MVN_FLAGS) -q -Pquick -pl alpine/alpine-model,apiserver process-classes
.PHONY: datanucleus-enhance

install:
	$(MVND) $(MVN_FLAGS) -q -Pquick install
.PHONY: install

lint-java:
	$(MVND) $(MVN_FLAGS) -q -Dmaven.build.cache.enabled=false validate
.PHONY: lint-java

lint-openapi:
	@dups=$$(find api/src/main/openapi -path '*/schemas/*.yaml' -exec basename {} \; \
		| sort | uniq -d); \
	if [ -n "$$dups" ]; then \
		echo "Duplicate schema basenames (must be globally unique):"; \
		echo "$$dups"; \
		exit 1; \
	fi
	docker run --rm -i -w /work \
		--platform linux/amd64 \
		-v "$(CURDIR)/api:/work" \
		stoplight/spectral lint \
		--ruleset src/main/spectral/ruleset.yaml \
		src/main/openapi/openapi.yaml
.PHONY: lint-openapi

lint-proto:
	buf lint
.PHONY: lint-proto

lint: lint-java lint-openapi lint-proto
.PHONY: lint

test:
	$(MVND) $(MVN_FLAGS) -Dcheckstyle.skip -Dcyclonedx.skip verify
.PHONY: test

test-single:
	$(MVND) $(MVN_FLAGS) test \
		-Dmaven.build.cache.enabled=false \
		-Dcheckstyle.skip \
		-Dcyclonedx.skip \
		-pl "$(MODULE)" \
		-am \
		-Dtest="$(TEST)"
.PHONY: test-single

new-migration:
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make new-migration NAME=\"short description\""; \
		exit 1; \
	fi; \
	slug=$$(printf '%s' "$(NAME)" | tr '[:upper:]' '[:lower:]' \
		| sed -e 's/[^a-z0-9]\{1,\}/_/g' -e 's/^_//' -e 's/_$$//'); \
	if [ -z "$$slug" ]; then \
		echo "NAME must contain at least one alphanumeric character"; \
		exit 1; \
	fi; \
	ts=$$(date -u +%Y%m%d%H%M); \
	dir="migration/src/main/resources/org/dependencytrack/migration"; \
	if ls "$$dir"/V$${ts}__*.sql >/dev/null 2>&1; then \
		echo "A migration with version $$ts already exists; wait a minute and retry"; \
		exit 1; \
	fi; \
	path="$$dir/V$${ts}__$${slug}.sql"; \
	: > "$$path"; \
	echo "$$path"
.PHONY: new-migration

apiserver-dev:
	$(MVN) $(MVN_FLAGS) -q -Pquick,dev-services -pl apiserver -am verify
.PHONY: apiserver-dev

test-e2e: build-image
	$(MVND) $(MVN_FLAGS) -pl e2e -DskipE2E=false verify
.PHONY: test-e2e

clean:
	$(MVND) $(MVN_FLAGS) -q -Dmaven.build.cache.enabled=false clean
.PHONY: clean

clean-build-cache:
	rm -r "$${HOME}/.m2/build-cache/v1.1/org.dependencytrack/"
.PHONY: clean-build-cache

update-distro-info:
	curl -fsSL -o support/os-distro-metadata/src/main/resources/org/dependencytrack/support/distrometadata/debian.csv \
		https://debian.pages.debian.net/distro-info-data/debian.csv
	curl -fsSL -o support/os-distro-metadata/src/main/resources/org/dependencytrack/support/distrometadata/ubuntu.csv \
		https://debian.pages.debian.net/distro-info-data/ubuntu.csv
	curl -fsSL -o support/os-distro-metadata/src/main/resources/org/dependencytrack/support/distrometadata/LICENSE \
		https://salsa.debian.org/debian/distro-info-data/-/raw/main/debian/copyright
.PHONY: update-distro-info
