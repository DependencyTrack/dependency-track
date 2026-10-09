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
package org.dependencytrack.model.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.UUID;

/**
 * @since 5.3.0
 */
public class ValidUuidListValidator implements ConstraintValidator<ValidUuidList, String> {

    @Override
    public boolean isValid(final String uuidList, final ConstraintValidatorContext validatorContext) {
        if (uuidList == null) {
            // null-ness is expected to be validated using @NotNull / required path params
            return true;
        }

        // Keep empty segments invalid (e.g. "uuid|" or "|uuid") so callers get a 400
        // instead of a parse exception deeper in the resource method.
        final String[] parts = uuidList.split("\\|", -1);
        if (parts.length == 0) {
            return false;
        }

        for (final String part : parts) {
            if (part.isEmpty()) {
                return false;
            }
            try {
                UUID.fromString(part);
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        return true;
    }
}
