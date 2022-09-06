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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
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
        testLoadDefaultConfigProperties();
        testLoadDefaultNotificationPublishers();
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
        Assert.assertEquals(Permissions.values().length, qm.getPermissions().size());
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
        Assert.assertEquals(13, qm.getAllRepositories().size());
    }

    @Test
    public void testLoadDefaultConfigProperties() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultConfigProperties");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(ConfigPropertyConstants.values().length, qm.getConfigProperties().size());
    }

    @Test
    public void testLoadDefaultNotificationPublishers() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultNotificationPublishers");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(DefaultNotificationPublishers.values().length, qm.getAllNotificationPublishers().size());
    }
}
