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
import org.junit.Assert;
import org.junit.Test;
import java.lang.reflect.Method;

public class DefaultObjectGeneratorTest extends PersistenceCapableTest {

    @Test
    public void testContextInitialized() throws Exception {
        testLoadDefaultPermissions();
        testLoadDefaultPersonas();
        testLoadDefaultLicenses();
        testLoadDefaultRepositories();
        testLoadDefaultNotificicationPublishers();
        testLoadDefaultConfigProperties();
    }

    @Test
    public void testLoadDefaultLicenses() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultLicenses");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(489, qm.getAllLicensesConcise().size());
    }

    @Test
    public void testLoadDefaultPermissions() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultPermissions");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(9, qm.getPermissions().size());
    }

    @Test
    public void testLoadDefaultPersonas() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultPersonas");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(3, qm.getTeams().size());
    }

    @Test
    public void testLoadDefaultRepositories() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultRepositories");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(12, qm.getAllRepositories().size());
    }

    @Test
    public void testLoadDefaultConfigProperties() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultConfigProperties");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(37, qm.getConfigProperties().size());
    }

    @Test
    public void testLoadDefaultNotificicationPublishers() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultNotificicationPublishers");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(5, qm.getAllNotificationPublishers().size());
    }
}
