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

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import jakarta.validation.ReportAsSingleViolation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * Validates a pipe-separated list of UUIDs (a single UUID is also accepted).
 * <p>
 * Used where path/query parameters encode multiple IDs as {@code uuid|uuid|…}.
 * {@link ValidUuid} is intentionally not used there — it would reject anything
 * that is not a solitary UUID string.
 *
 * @since 5.3.0
 */
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.TYPE_USE})
@Constraint(validatedBy = ValidUuidListValidator.class)
@Retention(RUNTIME)
@ReportAsSingleViolation
public @interface ValidUuidList {

    String message() default "Invalid UUID";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
