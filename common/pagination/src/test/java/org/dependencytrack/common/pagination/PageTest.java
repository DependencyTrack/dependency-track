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
package org.dependencytrack.common.pagination;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class PageTest {

    @Test
    void shouldThrowWhenItemsIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new Page<>(null))
                .withMessage("items must not be null");
    }

    @Test
    void withTotalCountShouldPopulateTotalCountField() {
        final var page = new Page<>(List.of("foo"))
                .withTotalCount(1, Page.TotalCount.Type.EXACT);

        assertThat(page.items()).containsOnly("foo");
        assertThat(page.totalCount()).isNotNull();
        assertThat(page.totalCount().value()).isEqualTo(1);
        assertThat(page.totalCount().type()).isEqualTo(Page.TotalCount.Type.EXACT);
    }

    @Nested
    class TotalCountTest {

        @Test
        void shouldThrowWhenValueIsNegative() {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> new Page.TotalCount(-1, Page.TotalCount.Type.EXACT))
                    .withMessage("value must not be negative");
        }

        @Test
        void shouldThrowWhenTypeIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new Page.TotalCount(0, null))
                    .withMessage("type must not be null");
        }

    }

}