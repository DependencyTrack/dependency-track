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
package org.dependencytrack.plugin.api.storage;

import static java.util.Objects.requireNonNull;

/**
 * Result of a compare-and-delete operation of an {@link KeyValueStore}.
 *
 * @since 5.0.0
 */
public sealed interface CompareAndDeleteResult {

    /**
     * Indicates that the operation failed.
     *
     * @param reason Reason for the failure.
     */
    record Failure(Reason reason) implements CompareAndDeleteResult {

        public enum Reason {

            /**
             * A matching record did either:
             * <ul>
             *     <li>Exist, but with a different version</li>
             *     <li>Not exist, e.g. because it was already deleted</li>
             * </ul>
             */
            VERSION_MISMATCH

        }

        public Failure {
            requireNonNull(reason, "reason must not be null");
        }

    }

    /**
     * Indicates that the operation completed successfully.
     */
    record Success() implements CompareAndDeleteResult {
    }

}
