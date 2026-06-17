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
package org.dependencytrack.dex;

import org.dependencytrack.dex.engine.api.DexEngine;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
@Liveness
public final class DexEngineHealthCheck implements HealthCheck {

    private final DexEngine engine;

    DexEngineHealthCheck(DexEngine engine) {
        this.engine = requireNonNull(engine, "engine must not be null");
    }

    @Override
    public HealthCheckResponse call() {
        return engine.probeHealth();
    }

}