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
package org.dependencytrack.persistence;

import alpine.model.ConfigProperty;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.model.Team;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.DefaultRepository;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Repository;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class DatabaseSeedingInitTaskTest extends PersistenceCapableTest {

    private DataSource dataSource;

    @BeforeEach
    public void before() throws Exception {
        super.before();

        dataSource = DataSourceRegistry.getInstance().getDefault();
    }

    @Test
    public void test() throws Exception {
        new DatabaseSeedingInitTask().execute(new InitTaskContext(ConfigProvider.getConfig(), dataSource));

        final List<ConfigProperty> configProperties = qm.getConfigProperties();
        assertThat(configProperties).hasSize(ConfigPropertyConstants.values().length);
        assertThat(configProperties).allSatisfy(property -> {
            assertThat(property.getGroupName()).isNotBlank();
            assertThat(property.getPropertyName()).isNotBlank();
            assertThat(property.getPropertyType()).isNotNull();
            assertThat(property.getDescription()).isNotNull();
        });
        assertThat(configProperties).anySatisfy(property -> assertThat(property.getPropertyValue()).isNotBlank());

        final List<Permission> permissions = qm.getPermissions();
        assertThat(permissions).hasSize(Permissions.values().length);
        assertThat(permissions).allSatisfy(permission -> {
            assertThat(permission.getName()).isNotBlank();
            assertThat(permission.getDescription()).isNotBlank();
        });

        final List<Team> teams = qm.getTeams().getList(Team.class);
        assertThat(teams).isNotEmpty();
        assertThat(teams).allSatisfy(team -> {
            assertThat(team.getName()).isNotBlank();
            assertThat(team.getUuid()).isNotNull();
            assertThat(team.getPermissions()).isNotEmpty();
        });

        final List<ManagedUser> users = qm.getManagedUsers();
        assertThat(users).satisfiesExactly(user -> {
            assertThat(user.getUsername()).isEqualTo("admin");
            assertThat(user.getEmail()).isEqualTo("admin@localhost");
            assertThat(user.getPassword()).isNotBlank();
            assertThat(user.getLastPasswordChange()).isNotNull();
            assertThat(user.isForcePasswordChange()).isTrue();
            assertThat(user.isNonExpiryPassword()).isTrue();
            assertThat(user.isSuspended()).isFalse();
            assertThat(user.getPermissions()).hasSize(Permissions.values().length);
            assertThat(user.getTeams()).extracting(Team::getName).containsOnly("Administrators");
        });

        final List<License> licenses = qm.getLicenses().getList(License.class);
        assertThat(licenses).isNotEmpty();
        assertThat(licenses).allSatisfy(license -> {
            assertThat(license.getLicenseId()).isNotBlank();
            assertThat(license.getName()).isNotBlank();
            assertThat(license.getUuid()).isNotNull();
        });
        assertThat(licenses).anySatisfy(license -> assertThat(license.getHeader()).isNotBlank());
        assertThat(licenses).anySatisfy(license -> assertThat(license.getHeader()).isNotBlank());
        assertThat(licenses).anySatisfy(license -> assertThat(license.getText()).isNotBlank());
        assertThat(licenses).anySatisfy(license -> assertThat(license.getTemplate()).isNotBlank());
        assertThat(licenses).anySatisfy(license -> assertThat(license.getComment()).isNotBlank());
        assertThat(licenses).anySatisfy(license -> assertThat(license.getSeeAlso()).isNotEmpty());

        final List<LicenseGroup> licenseGroups = qm.getLicenseGroups().getList(LicenseGroup.class);
        assertThat(licenseGroups).isNotEmpty();
        assertThat(licenseGroups).allSatisfy(licenseGroup -> {
            assertThat(licenseGroup.getName()).isNotBlank();
            assertThat(licenseGroup.getUuid()).isNotNull();
            assertThat(licenseGroup.getLicenses()).isNotEmpty();
        });

        final List<Repository> repositories = qm.getRepositories().getList(Repository.class);
        assertThat(repositories).hasSize(DefaultRepository.values().length);
        assertThat(repositories).allSatisfy(repository -> {
            assertThat(repository.getType()).isNotNull();
            assertThat(repository.getIdentifier()).isNotBlank();
            assertThat(repository.getUrl()).isNotBlank();
            assertThat(repository.getResolutionOrder()).isNotZero();
            assertThat(repository.isEnabled()).isTrue();
            assertThat(repository.getUuid()).isNotNull();
        });
    }

    @Test
    public void testWithDefaultObjectsAlreadyPopulated() throws Exception {
        new DatabaseSeedingInitTask().execute(new InitTaskContext(ConfigProvider.getConfig(), dataSource));

        List<License> licenses = qm.getLicenses().getList(License.class);
        assertThat(licenses).isNotEmpty();

        qm.delete(licenses);

        new DatabaseSeedingInitTask().execute(new InitTaskContext(ConfigProvider.getConfig(), dataSource));

        // Default objects must not have been populated again, since their
        // version is already current for this application build.
        licenses = qm.getLicenses().getList(License.class);
        assertThat(licenses).isEmpty();
    }

    @Test
    public void testLoadDefaultLicensesUpdatesExistingLicenses() throws Exception {
        final var license = new License();
        license.setLicenseId("LGPL-2.1+");
        license.setName("name");
        license.setComment("comment");
        license.setHeader("header");
        license.setSeeAlso("seeAlso");
        license.setTemplate("template");
        license.setText("text");
        qm.persist(license);

        new DatabaseSeedingInitTask().execute(new InitTaskContext(ConfigProvider.getConfig(), dataSource));

        qm.getPersistenceManager().refresh(license);
        assertThat(license.getLicenseId()).isEqualTo("LGPL-2.1+");
        assertThat(license.getName()).isEqualTo("GNU Lesser General Public License v2.1 or later");
        assertThat(license.getComment()).isNotEqualTo("comment");
        assertThat(license.getHeader()).isNotEqualTo("header");
        assertThat(license.getSeeAlso()).isNotEqualTo(new String[]{"seeAlso"});
        assertThat(license.getTemplate()).isNotEqualTo("template");
        assertThat(license.getText()).isNotEqualTo("text");
    }

}