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
package org.dependencytrack.integrations.kenna;

import alpine.model.IConfigProperty;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.persistence.QueryManager;
import org.junit.Assert;
import org.junit.Test;
import java.io.InputStream;

import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_CONNECTOR_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_ENABLED;

public class KennaSecurityUploaderTest extends PersistenceCapableTest {

    @Test
    public void testIntegrationMetadata() {
        KennaSecurityUploader extension = new KennaSecurityUploader();
        Assert.assertEquals("Kenna Security", extension.name());
        Assert.assertEquals("Pushes Dependency-Track findings to Kenna Security", extension.description());
    }

    @Test
    public void testIntegrationEnabledCases() {
        qm.createConfigProperty(
                KENNA_ENABLED.getGroupName(),
                KENNA_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        qm.createConfigProperty(
                KENNA_ENABLED.getGroupName(),
                KENNA_CONNECTOR_ID.getPropertyName(),
                "Dependency-Track (KDI)",
                IConfigProperty.PropertyType.STRING,
                null
        );
        KennaSecurityUploader extension = new KennaSecurityUploader();
        extension.setQueryManager(qm);
        Assert.assertTrue(extension.isEnabled());
    }

    @Test
    public void testIntegrationDisabledCases() {
        KennaSecurityUploader extension = new KennaSecurityUploader();
        extension.setQueryManager(qm);
        Assert.assertFalse(extension.isEnabled());
    }

    @Test
    public void testIntegrationFindings() throws Exception {
        KennaSecurityUploader extension = new KennaSecurityUploader();
        extension.setQueryManager(qm);
        InputStream in = extension.process();
        Assert.assertTrue(in != null && in.available() > 0);
    }
}
