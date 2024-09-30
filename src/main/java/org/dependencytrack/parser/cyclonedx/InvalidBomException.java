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
package org.dependencytrack.parser.cyclonedx;

import java.util.Collections;
import java.util.List;

/**
 * @since 4.11.0
 */
public class InvalidBomException extends RuntimeException {

    private final List<String> validationErrors;

    InvalidBomException(final String message) {
        this(message, (Throwable) null);
    }

    InvalidBomException(final String message, final Throwable cause) {
        this(message, cause, Collections.emptyList());
    }

    InvalidBomException(final String message, final List<String> validationErrors) {
        this(message, null, validationErrors);
    }

    private InvalidBomException(final String message, final Throwable cause, final List<String> validationErrors) {
        super(message, cause);
        this.validationErrors = validationErrors;
    }

    public List<String> getValidationErrors() {
        return validationErrors;
    }

}
