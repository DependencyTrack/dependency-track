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
package org.dependencytrack.auth.workloadidentity;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class WorkloadIdentityConditionEnvTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "claims.exp > claims.iat",
                "claims.exp - claims.iat <= 300",
                "claims.exp > 1700000000",
                "'https://dependency-track.example.com' in claims.aud",
                "claims.run_attempt == 2",
                "claims.context.environment == 'production'",
                "claims.sub.startsWith('repo:acme/app:ref:refs/heads/')",
                "has(claims.environment) && claims.environment == null"
            })
    void claimsMatcherShouldMatchClaimsOfAnyJsonType(String condition) {
        final String claimsJson = /* language=JSON */ """
            {
              "sub": "repo:acme/app:ref:refs/heads/main",
              "aud": [
                "https://dependency-track.example.com",
                "https://other.example.com"
              ],
              "iat": 1800000000,
              "exp": 1800000300,
              "run_attempt": 2,
              "context": {
                "environment": "production"
              },
              "environment": null
            }
            """;

        assertThat(WorkloadIdentityConditionEnv.getInstance().matcher(claimsJson))
                .accepts(condition);
    }
}
