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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

public class LicenseTest {

    @Test
    public void testId() {
        License license = new License();
        license.setId(111L);
        Assert.assertEquals(111L, license.getId());
    }

    @Test
    public void testName() {
        License license = new License();
        license.setName("Apache License 2.0");
        Assert.assertEquals("Apache License 2.0", license.getName());
    }

    @Test
    public void testText() {
        License license = new License();
        license.setText("License text");
        Assert.assertEquals("License text", license.getText());
    }

    @Test
    public void testTemplate() {
        License license = new License();
        license.setTemplate("License template");
        Assert.assertEquals("License template", license.getTemplate());
    }

    @Test
    public void testHeader() {
        License license = new License();
        license.setHeader("License header");
        Assert.assertEquals("License header", license.getHeader());
    }

    @Test
    public void testComment() {
        License license = new License();
        license.setComment("License comment");
        Assert.assertEquals("License comment", license.getComment());
    }

    @Test
    public void testLicenseId() {
        License license = new License();
        license.setLicenseId("Apache-2.0");
        Assert.assertEquals("Apache-2.0", license.getLicenseId());
    }

    @Test
    public void tesOsiApproved() {
        License license = new License();
        license.setOsiApproved(true);
        Assert.assertTrue(license.isOsiApproved());
    }

    @Test
    public void tesFsfLibre() {
        License license = new License();
        license.setFsfLibre(true);
        Assert.assertTrue(license.isFsfLibre());
    }

    @Test
    public void testDeprecatedLicenseId() {
        License license = new License();
        license.setDeprecatedLicenseId(true);
        Assert.assertTrue(license.isDeprecatedLicenseId());
    }

    @Test
    public void testSeeAlso() {
        License license = new License();
        license.setSeeAlso("url #1", "url #2");
        Assert.assertEquals(2, license.getSeeAlso().length);
        Assert.assertEquals("url #1", license.getSeeAlso()[0]);
        Assert.assertEquals("url #2", license.getSeeAlso()[1]);
    }

    @Test
    public void testLicenseGroups() {
        License license = new License();
        LicenseGroup lg = new LicenseGroup();
        lg.setName("Copyleft");
        license.setLicenseGroups(Collections.singletonList(lg));
        Assert.assertEquals(1, license.getLicenseGroups().size());
        Assert.assertEquals("Copyleft", license.getLicenseGroups().get(0).getName());
    }

    @Test
    public void testUuid() {
        UUID uuid = UUID.randomUUID();
        License license = new License();
        license.setUuid(uuid);
        Assert.assertEquals(uuid.toString(), license.getUuid().toString());
    }
}
