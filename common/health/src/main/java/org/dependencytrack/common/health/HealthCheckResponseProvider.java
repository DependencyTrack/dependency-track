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
package org.dependencytrack.common.health;

/**
 * Implementation of the MicroProfile Health SPI.
 *
 * @see <a href="https://download.eclipse.org/microprofile/microprofile-health-3.1/microprofile-health-spec-3.1.html#_spi_usage">MicroProfile Health SPI Usage</a>
 * @since 5.0.0
 */
public final class HealthCheckResponseProvider implements org.eclipse.microprofile.health.spi.HealthCheckResponseProvider {

    @Override
    public org.eclipse.microprofile.health.HealthCheckResponseBuilder createResponseBuilder() {
        return new HealthCheckResponseBuilder();
    }

}
