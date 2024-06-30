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
package org.dependencytrack.exception;

import java.util.Map;

/**
 * @since 4.12.0
 */
public class TagOperationFailedException extends IllegalStateException {

    private final Map<String, String> errorByTagName;

    private TagOperationFailedException(final String message, final Map<String, String> errorByTagName) {
        super(message);
        this.errorByTagName = errorByTagName;
    }

    public static TagOperationFailedException forDeletion(final Map<String, String> errorByTagName) {
        return new TagOperationFailedException("The tag(s) %s could not be deleted"
                .formatted(String.join(",", errorByTagName.keySet())), errorByTagName);
    }

    public Map<String, String> getErrorByTagName() {
        return errorByTagName;
    }

}
