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
package org.dependencytrack.model;

import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DefaultRepositoryTest {

    @Test
    public void shouldNotHaveDuplicateResolutionOrdersPerType() {
        final Map<RepositoryType, List<Integer>> defaultRepoByType =
                Arrays.stream(DefaultRepository.values()).collect(
                        Collectors.groupingBy(
                                DefaultRepository::getType,
                                Collectors.mapping(
                                        DefaultRepository::getResolutionOrder,
                                        Collectors.toList())));

        final var softAsserts = new SoftAssertions();
        for (final RepositoryType type : RepositoryType.values()) {
            final List<Integer> defaultRepos = defaultRepoByType.get(type);
            if (defaultRepos != null) {
                softAsserts.assertThat(defaultRepos).doesNotHaveDuplicates();
            }
        }

        softAsserts.assertAll();
    }

}