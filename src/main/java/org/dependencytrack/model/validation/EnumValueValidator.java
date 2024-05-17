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
import java.util.Arrays;
import java.util.Set;

/**
 * @since 4.11.0
 */
public class EnumValueValidator implements ConstraintValidator<EnumValue, Enum<?>> {

    private Set<String> disallowedValues;

    @Override
    public void initialize(final EnumValue constraintAnnotation) {
        disallowedValues = Set.copyOf(Arrays.asList(constraintAnnotation.disallowed()));
    }

    @Override
    public boolean isValid(final Enum<?> value, final ConstraintValidatorContext context) {
        if (value == null) {
            return true;
        }

        return !disallowedValues.contains(value.name());
    }

}
