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

import org.junit.Before;
import org.junit.Test;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class SpdxExpressionValidatorTest {

    private Validator validator;

    private record TestRecord(@ValidSpdxExpression String expression) {
    }

    @Before
    public void setUp() {
        final ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @Test
    public void testWithValidExpression() {
        final Set<ConstraintViolation<TestRecord>> violations = validator.validate(new TestRecord("Apache-2.0 OR MIT"));
        assertThat(violations).isEmpty();
    }

    @Test
    public void testWithInvalidExpression() {
        final Set<ConstraintViolation<TestRecord>> violations = validator.validate(new TestRecord("(Apache-2.0"));
        assertThat(violations).isNotEmpty();
    }

    @Test
    public void testWithNullExpression() {
        final Set<ConstraintViolation<TestRecord>> violations = validator.validate(new TestRecord(null));
        assertThat(violations).isEmpty();
    }

}