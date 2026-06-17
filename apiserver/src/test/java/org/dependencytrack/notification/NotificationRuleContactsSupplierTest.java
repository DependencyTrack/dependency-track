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
package org.dependencytrack.notification;

import alpine.model.OidcUser;
import alpine.model.Team;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class NotificationRuleContactsSupplierTest extends PersistenceCapableTest {

    private NotificationRule rule;

    @BeforeEach
    void beforeEach() {
        final NotificationPublisher publisher = qm.createNotificationPublisher(
                "test",
                "description",
                "extensionName",
                "templateContent",
                "templateMimeType",
                false);

        rule = qm.createNotificationRule(
                "test",
                NotificationScope.PORTFOLIO,
                NotificationLevel.INFORMATIONAL,
                publisher);
    }

    @Test
    void shouldReturnEmptySetWhenRuleHasNoTeams() {
        final var supplier = new NotificationRuleContactsSupplier(rule.getName());

        assertThat(supplier.get()).isEmpty();
    }

    @Test
    void shouldReturnEmptySetWhenTeamHasNoUsers() {
        final var team = new Team();
        team.setName("test");
        qm.persist(team);

        rule.setTeams(Set.of(team));

        final var supplier = new NotificationRuleContactsSupplier(rule.getName());

        assertThat(supplier.get()).isEmpty();
    }

    @Test
    void shouldReturnSetOfUserContacts() {
        final var user = new OidcUser();
        user.setUsername("test");
        user.setEmail("test@example.com");
        qm.persist(user);

        final var team = new Team();
        team.setName("test");
        team.setUsers(List.of(user));
        qm.persist(team);

        rule.setTeams(Set.of(team));

        final var supplier = new NotificationRuleContactsSupplier(rule.getName());

        assertThat(supplier.get()).satisfiesExactly(contact -> {
            assertThat(contact.username()).isEqualTo("test");
            assertThat(contact.email()).isEqualTo("test@example.com");
        });
    }

}