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
 * Defines types of health checks supported by MicroProfile Health.
 *
 * @see <a href="https://download.eclipse.org/microprofile/microprofile-health-3.1/microprofile-health-spec-3.1.html#_different_kinds_of_health_checks">MicroProfile Health Specification</a>
 * @see <a href="https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/">Probes in Kubernetes</a>
 * @since 5.0.0
 */
public enum HealthCheckType {

    /**
     * Liveness probes may be used by service orchestrators to evaluate
     * whether a service instance needs to be restarted.
     */
    LIVENESS,

    /**
     * Readiness probes may be used by service orchestrators to evaluate
     * whether a service instance is ready to accept traffic.
     */
    READINESS,

    /**
     * Startup probes may be used by service orchestrators to evaluate
     * whether a service instance has started.
     */
    STARTUP,

    /**
     * Probes that either do not specify their type, or apply to all types.
     */
    ALL

}
