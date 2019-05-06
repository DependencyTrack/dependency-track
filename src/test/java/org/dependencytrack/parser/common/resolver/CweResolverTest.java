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
package org.dependencytrack.parser.common.resolver;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Cwe;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CweResolverTest extends PersistenceCapableTest {

    @Before
    public void before() throws Exception {
        super.before();
        qm.createCweIfNotExist(79, "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')");
    }

    @Test
    public void testPositiveResolutionByCweId() {
        CweResolver resolver = new CweResolver(qm);
        Cwe cwe = resolver.resolve("CWE-79");
        Assert.assertNotNull(cwe);
        Assert.assertEquals(79, cwe.getCweId());
    }

    @Test
    public void testPositiveResolutionByCweIdIntegerOnly() {
        CweResolver resolver = new CweResolver(qm);
        Cwe cwe = resolver.resolve("79");
        Assert.assertNotNull(cwe);
        Assert.assertEquals(79, cwe.getCweId());
    }

    @Test
    public void testPositiveResolutionByCweIdAndName() {
        CweResolver resolver = new CweResolver(qm);
        Cwe cwe = resolver.resolve("CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')");
        Assert.assertNotNull(cwe);
        Assert.assertEquals(79, cwe.getCweId());
    }

    @Test
    public void testNegativeResolutionByCweId() {
        CweResolver resolver = new CweResolver(qm);
        Cwe cwe = resolver.resolve("CWE-9999");
        Assert.assertNull(cwe);
    }

    @Test
    public void testNegativeResolutionByInvalidCweId() {
        CweResolver resolver = new CweResolver(qm);
        Cwe cwe = resolver.resolve("CWE-A");
        Assert.assertNull(cwe);
    }
}
