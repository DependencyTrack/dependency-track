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
package org.dependencytrack.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.UUID;

class BomTest {

    @Test
    void testId() {
        Bom bom = new Bom();
        bom.setId(111L);
        Assertions.assertEquals(111L, bom.getId());
    }

    @Test
    void testImported() {
        Date date = new Date();
        Bom bom = new Bom();
        bom.setImported(date);
        Assertions.assertEquals(date, bom.getImported());
    }

    @Test
    void testProject() {
        Project project = new Project();
        Bom bom = new Bom();
        bom.setProject(project);
        Assertions.assertEquals(project, bom.getProject());
    }

    @Test
    void testUuid() {
        UUID uuid = UUID.randomUUID();
        Bom bom = new Bom();
        bom.setUuid(uuid);
        Assertions.assertEquals(uuid.toString(), bom.getUuid().toString());
    }

    @Test
    void testBomFormat() {
        Bom bom = new Bom();
        bom.setBomFormat(Bom.Format.CYCLONEDX);
        Assertions.assertEquals(Bom.Format.CYCLONEDX.getFormatShortName(), bom.getBomFormat());
    }

    @Test
    void testBomSpecVersion() {
        Bom bom = new Bom();
        bom.setSpecVersion("1.1");
        Assertions.assertEquals("1.1", bom.getSpecVersion());
    }
}
