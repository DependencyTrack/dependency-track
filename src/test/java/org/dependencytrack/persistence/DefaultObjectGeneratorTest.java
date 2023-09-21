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

import alpine.model.ConfigProperty;
import alpine.server.auth.PasswordService;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

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
        clearEnvironmentVariable(DefaultObjectGenerator.ADMIN_USERNAME_ENV_VARIABLE);
        clearEnvironmentVariable(DefaultObjectGenerator.ADMIN_PASSWORD_ENV_VARIABLE);
        clearEnvironmentVariable(DefaultObjectGenerator.ADMIN_FULL_NAME_ENV_VARIABLE);
        clearEnvironmentVariable(DefaultObjectGenerator.ADMIN_EMAIL_ENV_VARIABLE);
        Method method = generator.getClass().getDeclaredMethod("loadDefaultPersonas");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(3, qm.getTeams().size());
        var users = qm.getManagedUsers();
        Assert.assertEquals(1, users.size());
        Assert.assertEquals(DefaultObjectGenerator.DEFAULT_ADMIN_USERNAME, users.get(0).getUsername());
        Assert.assertTrue(PasswordService.matches(DefaultObjectGenerator.DEFAULT_ADMIN_PASSWORD.toCharArray(), users.get(0)));
        Assert.assertEquals(DefaultObjectGenerator.DEFAULT_ADMIN_FULL_NAME, users.get(0).getFullname());
        Assert.assertEquals(DefaultObjectGenerator.DEFAULT_ADMIN_EMAIL, users.get(0).getEmail());
    }

    @Test
    public void testLoadDefaultPersonasWithUserProvidedCredentials() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        setEnvironmentVariable(DefaultObjectGenerator.ADMIN_USERNAME_ENV_VARIABLE, "test");
        setEnvironmentVariable(DefaultObjectGenerator.ADMIN_PASSWORD_ENV_VARIABLE, "testPassword");
        setEnvironmentVariable(DefaultObjectGenerator.ADMIN_FULL_NAME_ENV_VARIABLE, "test test");
        setEnvironmentVariable(DefaultObjectGenerator.ADMIN_EMAIL_ENV_VARIABLE, "test@test.dev");
        Method method = generator.getClass().getDeclaredMethod("loadDefaultPersonas");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(3, qm.getTeams().size());
        var users = qm.getManagedUsers();
        Assert.assertEquals(1, users.size());
        Assert.assertEquals("test", users.get(0).getUsername());
        Assert.assertTrue(PasswordService.matches("testPassword".toCharArray(), users.get(0)));
        Assert.assertEquals("test test", users.get(0).getFullname());
        Assert.assertEquals("test@test.dev", users.get(0).getEmail());
    }

    @Test
    public void testLoadDefaultRepositories() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultRepositories");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(14, qm.getAllRepositories().size());
    }

    @Test
    public void testLoadDefaultConfigProperties() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        String nvdToggleEnvVariableName = generator.generateEnvVariableName(ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED);
        setEnvironmentVariable(nvdToggleEnvVariableName, "false");
        Method method = generator.getClass().getDeclaredMethod("loadDefaultConfigProperties");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(ConfigPropertyConstants.values().length, qm.getConfigProperties().size());
        ConfigProperty nvdEnabled = qm.getConfigProperty(ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED.getGroupName(), ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyName());
        Assert.assertEquals("false", nvdEnabled.getPropertyValue());
    }

    @Test
    public void testLoadDefaultNotificationPublishers() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        Method method = generator.getClass().getDeclaredMethod("loadDefaultNotificationPublishers");
        method.setAccessible(true);
        method.invoke(generator);
        Assert.assertEquals(DefaultNotificationPublishers.values().length, qm.getAllNotificationPublishers().size());
    }

    private static void clearEnvironmentVariable(String key) throws Exception {
        Class<?> processEnvironment = Class.forName("java.lang.ProcessEnvironment");

        Field unmodifiableMapField = getAccessibleField(processEnvironment, "theUnmodifiableEnvironment");
        Object unmodifiableMap = unmodifiableMapField.get(null);
        clearUnmodifiableMap(key, unmodifiableMap);

        try {
            Field caseInsensitiveMapField = getAccessibleField(processEnvironment, "theCaseInsensitiveEnvironment");
            Map<String, String> caseInsensitiveMap = (Map<String, String>) caseInsensitiveMapField.get(null);
            caseInsensitiveMap.remove(key);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
            // Nothing to be done, the attribute presence depend on the JVM
        }

        Field mapField = getAccessibleField(processEnvironment, "theEnvironment");
        Map<String, String> map = (Map<String, String>) mapField.get(null);
        map.remove(key);
    }

    private static void setEnvironmentVariable(String key, String value) throws Exception {

        Class<?> processEnvironment = Class.forName("java.lang.ProcessEnvironment");

        Field unmodifiableMapField = getAccessibleField(processEnvironment, "theUnmodifiableEnvironment");
        Object unmodifiableMap = unmodifiableMapField.get(null);
        injectIntoUnmodifiableMap(key, value, unmodifiableMap);

        try {
            Field caseInsensitiveMapField = getAccessibleField(processEnvironment, "theCaseInsensitiveEnvironment");
            Map<String, String> caseInsensitiveMap = (Map<String, String>) caseInsensitiveMapField.get(null);
            caseInsensitiveMap.put(key, value);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
            // Nothing to be done, the attribute presence depend on the JVM
        }

        Field mapField = getAccessibleField(processEnvironment, "theEnvironment");
        Map<String, String> map = (Map<String, String>) mapField.get(null);
        map.put(key, value);
    }

    private static Field getAccessibleField(Class<?> clazz, String fieldName)
            throws NoSuchFieldException {

        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field;
    }

    private static void injectIntoUnmodifiableMap(String key, String value, Object map)
            throws ReflectiveOperationException {

        Class unmodifiableMap = Class.forName("java.util.Collections$UnmodifiableMap");
        Field field = getAccessibleField(unmodifiableMap, "m");
        Object obj = field.get(map);
        ((Map<String, String>) obj).put(key, value);
    }

    private static void clearUnmodifiableMap(String key, Object map)
            throws ReflectiveOperationException {

        Class unmodifiableMap = Class.forName("java.util.Collections$UnmodifiableMap");
        Field field = getAccessibleField(unmodifiableMap, "m");
        Object obj = field.get(map);
        ((Map<String, String>) obj).remove(key);
    }
}
