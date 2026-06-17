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
package org.dependencytrack.dex.api.failure;

import org.jspecify.annotations.Nullable;

/**
 * A {@link FailureException} indicating a terminal failure in application code that shall not be retried.
 */
public class TerminalApplicationFailureException extends ApplicationFailureException {

    public TerminalApplicationFailureException(
            @Nullable String message,
            @Nullable Throwable cause) {
        super(message, cause, /* isTerminal */ true);
    }

    public TerminalApplicationFailureException(@Nullable String message) {
        this(message, null);
    }

    public TerminalApplicationFailureException(@Nullable Throwable cause) {
        this(null, cause);
    }

}
