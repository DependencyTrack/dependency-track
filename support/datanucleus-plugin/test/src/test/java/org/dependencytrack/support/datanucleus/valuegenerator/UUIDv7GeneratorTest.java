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
package org.dependencytrack.support.datanucleus.valuegenerator;

import org.dependencytrack.support.datanucleus.AbstractTest;
import org.dependencytrack.support.datanucleus.test.Person;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class UUIDv7GeneratorTest extends AbstractTest {

    @Test
    void test() {
        final var uuidsSeen = new HashSet<UUID>();
        for (int i = 0; i < 10; i++) {
            final var person = new Person();
            person.setName("person-" + i);
            pm.makePersistent(person);

            assertThat(uuidsSeen.add(person.getUuid())).isTrue();
        }
    }

}
