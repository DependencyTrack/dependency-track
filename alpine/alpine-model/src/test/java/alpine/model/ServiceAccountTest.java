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
package alpine.model;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class ServiceAccountTest {

    @ParameterizedTest
    @CsvSource({
            "svc-ci, true",
            "SVC-ci, true",
            "Svc-ci, true",
            "svc-, true",
            "svc, false",
            "svcci, false",
            "svc_ci, false",
            "xsvc-ci, false",
            "'', false",
    })
    void hasReservedPrefixShouldIgnoreCase(String username, boolean expected) {
        assertThat(ServiceAccount.hasReservedPrefix(username)).isEqualTo(expected);
    }
}
