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
package org.dependencytrack.policy;

import java.time.Duration;

/**
 * Thrown when policy evaluation exceeds its configured maximum duration.
 *
 * @since 5.0.0
 */
public final class PolicyEvaluationTimedOutException extends RuntimeException {

    private final Duration maxDuration;

    public PolicyEvaluationTimedOutException(Duration maxDuration) {
        super("Policy evaluation exceeded maximum duration of %s".formatted(maxDuration));
        this.maxDuration = maxDuration;
    }

    public Duration maxDuration() {
        return maxDuration;
    }

}
