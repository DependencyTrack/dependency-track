/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.pkgmetadata.resolution.api;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class PackageRepositoryTest {

    @Test
    void shouldThrowWhenNameIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new PackageRepository(null, "https://example.com", null, null))
                .withMessage("name must not be null");
    }

    @Test
    void shouldThrowWhenUrlIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new PackageRepository("example", null, null, null))
                .withMessage("url must not be null");
    }

}