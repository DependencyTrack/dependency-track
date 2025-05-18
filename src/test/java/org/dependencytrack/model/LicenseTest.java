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

import java.util.Collections;
import java.util.UUID;

class LicenseTest {

    @Test
    void testId() {
        License license = new License();
        license.setId(111L);
        Assertions.assertEquals(111L, license.getId());
    }

    @Test
    void testName() {
        License license = new License();
        license.setName("Apache License 2.0");
        Assertions.assertEquals("Apache License 2.0", license.getName());
    }

    @Test
    void testText() {
        License license = new License();
        license.setText("License text");
        Assertions.assertEquals("License text", license.getText());
    }

    @Test
    void testTemplate() {
        License license = new License();
        license.setTemplate("License template");
        Assertions.assertEquals("License template", license.getTemplate());
    }

    @Test
    void testHeader() {
        License license = new License();
        license.setHeader("License header");
        Assertions.assertEquals("License header", license.getHeader());
    }

    @Test
    void testComment() {
        License license = new License();
        license.setComment("License comment");
        Assertions.assertEquals("License comment", license.getComment());
    }

    @Test
    void testLicenseId() {
        License license = new License();
        license.setLicenseId("Apache-2.0");
        Assertions.assertEquals("Apache-2.0", license.getLicenseId());
    }

    @Test
    void tesOsiApproved() {
        License license = new License();
        license.setOsiApproved(true);
        Assertions.assertTrue(license.isOsiApproved());
    }

    @Test
    void tesFsfLibre() {
        License license = new License();
        license.setFsfLibre(true);
        Assertions.assertTrue(license.isFsfLibre());
    }

    @Test
    void testDeprecatedLicenseId() {
        License license = new License();
        license.setDeprecatedLicenseId(true);
        Assertions.assertTrue(license.isDeprecatedLicenseId());
    }

    @Test
    void testCustomLicense() {
        License license = new License();
        license.setCustomLicense(true);
        Assertions.assertTrue(license.isCustomLicense());
    }

    @Test
    void testSeeAlso() {
        License license = new License();
        license.setSeeAlso("url #1", "url #2");
        Assertions.assertEquals(2, license.getSeeAlso().length);
        Assertions.assertEquals("url #1", license.getSeeAlso()[0]);
        Assertions.assertEquals("url #2", license.getSeeAlso()[1]);
    }

    @Test
    void testLicenseGroups() {
        License license = new License();
        LicenseGroup lg = new LicenseGroup();
        lg.setName("Copyleft");
        license.setLicenseGroups(Collections.singletonList(lg));
        Assertions.assertEquals(1, license.getLicenseGroups().size());
        Assertions.assertEquals("Copyleft", license.getLicenseGroups().get(0).getName());
    }

    @Test
    void testUuid() {
        UUID uuid = UUID.randomUUID();
        License license = new License();
        license.setUuid(uuid);
        Assertions.assertEquals(uuid.toString(), license.getUuid().toString());
    }
}
