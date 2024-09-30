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
 */
package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.core.Response;

import static org.assertj.core.api.Assertions.assertThat;

public class OidcResourceUnauthenticatedTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(OidcResource.class)
                    .register(ApiFilter.class));

    @Test
    public void isAvailableShouldReturnFalseWhenOidcIsNotAvailable() {
        final Response response = jersey.target(V1_OIDC + "/available")
                .request().get();

        assertThat(getPlainTextBody(response)).isEqualTo("false");
    }

}