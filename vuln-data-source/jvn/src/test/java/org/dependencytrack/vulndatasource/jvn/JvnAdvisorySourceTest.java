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
package org.dependencytrack.vulndatasource.jvn;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JvnAdvisorySourceTest {

    @Test
    void streamsMultipleVulinfosInDocumentOrder() throws Exception {
        // Duplicate the fixture's single <Vulinfo> under a second id, within the same root.
        final String fixtureXml = fixture();
        final int start = fixtureXml.indexOf("<Vulinfo>");
        final int end = fixtureXml.indexOf("</Vulinfo>") + "</Vulinfo>".length();
        final String vulinfo = fixtureXml.substring(start, end);
        final String secondVulinfo = vulinfo.replace("JVNDB-2026-022538", "JVNDB-2026-999999");
        final String doubledXml = fixtureXml.substring(0, end) + secondVulinfo + fixtureXml.substring(end);

        try (final var source = new JvnAdvisorySource(inputStream(doubledXml))) {
            assertTrue(source.hasNext());
            assertEquals("JVNDB-2026-022538", source.next().jvnDbId());
            assertTrue(source.hasNext());
            assertEquals("JVNDB-2026-999999", source.next().jvnDbId());
            assertFalse(source.hasNext());
        }
    }

    @Test
    void rejectsDoctypeDeclarations() throws Exception {
        final String xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe \"boom\">]>"
                + "<VULDEF-Document><Vulinfo><VulinfoID>&xxe;</VulinfoID></Vulinfo></VULDEF-Document>";

        try (final var source = new JvnAdvisorySource(inputStream(xml))) {
            assertThrows(IllegalArgumentException.class, source::hasNext);
        }
    }

    @Test
    void throwsOnTruncatedDocument() throws Exception {
        final String truncatedXml = fixture().substring(0, fixture().indexOf("</Vulinfo>"));

        try (final var source = new JvnAdvisorySource(inputStream(truncatedXml))) {
            assertThrows(IllegalArgumentException.class, () -> {
                while (source.hasNext()) {
                    source.next();
                }
            });
        }
    }

    private String fixture() throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/jvn-detail-with-range.xml")) {
            assertNotNull(in, "fixture jvn-detail-with-range.xml must be present");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static InputStream inputStream(final String xml) {
        return new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
    }
}
