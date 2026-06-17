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

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class ValidUuidValidatorTest {

    private Validator validator;

    private record TestRecord(@ValidUuid String uuid) {
    }

    @BeforeEach
    public void setUp() {
        final ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @Test
    public void testWithValidUuidV4() {
        final Set<ConstraintViolation<TestRecord>> violations = validator.validate(new TestRecord("6a80b854-8083-47ea-869c-321018c0ff76"));
        assertThat(violations).isEmpty();
    }

    @Test
    public void testWithValidUuidV7() {
        final Set<ConstraintViolation<TestRecord>> violations = validator.validate(new TestRecord("01942307-ebc3-7ec8-a66e-1a40d595c097"));
        assertThat(violations).isEmpty();
    }

    @Test
    public void testWithInvalidUuid() {
        final Set<ConstraintViolation<TestRecord>> violations = validator.validate(new TestRecord("invalid-uuid"));
        assertThat(violations).isNotEmpty();
    }

    @Test
    public void testWithNullUuid() {
        final Set<ConstraintViolation<TestRecord>> violations = validator.validate(new TestRecord(null));
        assertThat(violations).isEmpty();
    }

}