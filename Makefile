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
	$(MVND) $(MVN_FLAGS) -q \
		-Penhance,embedded-jetty,quick \
		-Dlogback.configuration.file=src/main/docker/logback.xml \
		package
.PHONY: build

build-bundled:
	$(MVND) $(MVN_FLAGS) -q \
		-Penhance,embedded-jetty,bundle-ui,quick \
		-Dlogback.configuration.file=src/main/docker/logback.xml \
		package
.PHONY: build-bundled

build-image: build
	docker build \
		-t dependencytrack/apiserver:local \
		-f src/main/docker/Dockerfile \
		--build-arg WAR_FILENAME=dependency-track-apiserver.jar \
		.
.PHONY: build-image

build-bundled-image: build-bundled
	docker build \
		-t dependencytrack/bundled:local \
		-f src/main/docker/Dockerfile \
		--build-arg WAR_FILENAME=dependency-track-bundled.jar \
		.
.PHONY: build-bundled-image

datanucleus-enhance:
	$(MVND) $(MVN_FLAGS) -Penhance,quick process-classes
.PHONY: datanucleus-enhance

lint-java:
	$(MVND) $(MVN_FLAGS) -q validate
.PHONY: lint-java

lint: lint-java
.PHONY: lint

test:
	$(MVND) $(MVN_FLAGS) -Dcheckstyle.skip -Dcyclonedx.skip verify
.PHONY: test

test-single:
	$(MVND) $(MVN_FLAGS) test \
		-Dcheckstyle.skip \
		-Dcyclonedx.skip \
		-Dtest="$(TEST)"
.PHONY: test-single

clean:
	$(MVND) $(MVN_FLAGS) -q clean
.PHONY: clean
