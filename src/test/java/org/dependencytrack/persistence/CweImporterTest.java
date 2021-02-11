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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Cwe;
import org.junit.Assert;
import org.junit.Test;

public class CweImporterTest extends PersistenceCapableTest {

    @Test
    public void testProcessCweDefinitions() throws Exception {
        CweImporter importer = new CweImporter();
        importer.processCweDefinitions();
        Cwe cwe79 = qm.getCweById(79);
        Assert.assertEquals("Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", cwe79.getName());
        Assert.assertEquals(1335, qm.getCwes().getTotal());
    }
}
