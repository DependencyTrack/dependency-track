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

import alpine.model.Team;
import alpine.notification.NotificationLevel;
import alpine.persistence.PaginatedResult;
import alpine.persistence.ScopedCustomization;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.Publisher;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.dependencytrack.util.PersistenceUtil.assertPersistent;
import static org.dependencytrack.util.PersistenceUtil.assertPersistentAll;

public class NotificationQueryManager extends QueryManager implements IQueryManager {


    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    NotificationQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    NotificationQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Creates a new NotificationRule.
     * @param name the name of the rule
     * @param scope the scope
     * @param level the level
     * @param publisher the publisher
     * @return a new NotificationRule
     */
    public NotificationRule createNotificationRule(String name, NotificationScope scope, NotificationLevel level, NotificationPublisher publisher) {
        return callInTransaction(() -> {
            final NotificationRule rule = new NotificationRule();
            rule.setName(name);
            rule.setScope(scope);
            rule.setNotificationLevel(level);
            rule.setPublisher(publisher);
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setEnabled(true);
            rule.setNotifyChildren(true);
            rule.setLogSuccessfulPublish(false);
            return persist(rule);
        });
    }

    /**
     * @since 4.13.0
     */
    @Override
    public NotificationRule createScheduledNotificationRule(
            final String name,
            final NotificationScope scope,
            final NotificationLevel level,
            final NotificationPublisher publisher) {
        final var rule = new NotificationRule();
        rule.setName(name);
        rule.setScope(scope);
        rule.setNotificationLevel(level);
        rule.setPublisher(publisher);
        rule.setTriggerType(NotificationTriggerType.SCHEDULE);
        rule.setEnabled(false);
        rule.setScheduleCron("0 * * * *");
        rule.setScheduleLastTriggeredAt(new Date());
        rule.setScheduleSkipUnchanged(false);
        rule.updateScheduleNextTriggerAt();
        return persist(rule);
    }

    /**
     * Updated an existing NotificationRule.
     * @param transientRule the rule to update
     * @return a NotificationRule
     */
    public NotificationRule updateNotificationRule(NotificationRule transientRule) {
        return callInTransaction(() -> {
            final var rule = getObjectByUuid(NotificationRule.class, transientRule.getUuid());
            if (transientRule.getTriggerType() != null
                && rule.getTriggerType() != transientRule.getTriggerType()) {
                throw new IllegalArgumentException("Trigger type can not be changed");
            }

            if (rule.getTriggerType() == NotificationTriggerType.SCHEDULE) {
                final List<NotificationGroup> invalidGroups = transientRule.getNotifyOn().stream()
                        .filter(group -> group.getSupportedTriggerType() != NotificationTriggerType.SCHEDULE)
                        .toList();
                if (!invalidGroups.isEmpty()) {
                    throw new IllegalArgumentException(
                            "Groups %s are not supported for trigger type %s".formatted(
                                    invalidGroups, rule.getTriggerType()));
                }

                rule.setScheduleCron(transientRule.getScheduleCron());
                rule.setScheduleSkipUnchanged(transientRule.isScheduleSkipUnchanged());
                rule.updateScheduleNextTriggerAt();
            } else if (rule.getTriggerType() == NotificationTriggerType.EVENT) {
                final List<NotificationGroup> invalidGroups = transientRule.getNotifyOn().stream()
                        .filter(group -> group.getSupportedTriggerType() != NotificationTriggerType.EVENT)
                        .toList();
                if (!invalidGroups.isEmpty()) {
                    throw new IllegalArgumentException(
                            "Groups %s are not supported for trigger type %s".formatted(
                                    invalidGroups, rule.getTriggerType()));
                }
            }

            rule.setName(transientRule.getName());
            rule.setEnabled(transientRule.isEnabled());
            rule.setNotifyChildren(transientRule.isNotifyChildren());
            rule.setLogSuccessfulPublish(transientRule.isLogSuccessfulPublish());
            rule.setNotificationLevel(transientRule.getNotificationLevel());
            rule.setPublisherConfig(transientRule.getPublisherConfig());
            rule.setNotifyOn(transientRule.getNotifyOn());
            bind(rule, resolveTags(transientRule.getTags()));
            return rule;
        });
    }

    /**
     * Returns a paginated list of all notification rules.
     *
     * @param triggerTypeFilter The {@link NotificationTriggerType} to filter by.
     * @return a paginated list of NotificationRules
     */
    public PaginatedResult getNotificationRules(final NotificationTriggerType triggerTypeFilter) {
        final var filterParts = new ArrayList<String>();
        final var filterParams = new HashMap<String, Object>();

        if (triggerTypeFilter != null) {
            filterParts.add("triggerType == :triggerType");
            filterParams.put("triggerType", triggerTypeFilter);
        }
        if (this.filter != null) {
            filterParts.add("name.toLowerCase().matches(:name) || publisher.name.toLowerCase().matches(:name)");
            filterParams.put("name", ".*" + filter.toLowerCase() + ".*");
        }

        final Query<NotificationRule> query = pm.newQuery(NotificationRule.class);
        if (!filterParts.isEmpty()) {
            query.setFilter(String.join(" && ", filterParts));
        }
        if (this.orderBy == null) {
            query.setOrdering("name asc");
        }
        return execute(query, filterParams);
    }

    /**
     * Retrieves all NotificationPublishers.
     * This method if designed NOT to provide paginated results.
     * @return list of all NotificationPublisher objects
     */
    @SuppressWarnings("unchecked")
    public List<NotificationPublisher> getAllNotificationPublishers() {
        final Query<NotificationPublisher> query = pm.newQuery(NotificationPublisher.class);
        query.getFetchPlan().addGroup(NotificationPublisher.FetchGroup.ALL.name());
        query.setOrdering("name asc");
        return (List<NotificationPublisher>)query.execute();
    }

    /**
     * Retrieves a NotificationPublisher by its name.
     * @param name The name of the NotificationPublisher
     * @return a NotificationPublisher
     */
    public NotificationPublisher getNotificationPublisher(final String name) {
        final Query<NotificationPublisher> query = pm.newQuery(NotificationPublisher.class, "name == :name");
        query.setRange(0, 1);
        return singleResult(query.execute(name));
    }

    /**
     * Retrieves a NotificationPublisher by its class.
     * @param clazz The Class of the NotificationPublisher
     * @return a NotificationPublisher
     */
    public NotificationPublisher getDefaultNotificationPublisher(final Class<? extends Publisher> clazz) {
        return getDefaultNotificationPublisher(clazz.getCanonicalName());
    }

    /**
     * Retrieves a NotificationPublisher by its class.
     * @param clazz The Class of the NotificationPublisher
     * @return a NotificationPublisher
     */
    private NotificationPublisher getDefaultNotificationPublisher(final String clazz) {
        final Query<NotificationPublisher> query = pm.newQuery(NotificationPublisher.class, "publisherClass == :publisherClass && defaultPublisher == true");
        query.getFetchPlan().addGroup(NotificationPublisher.FetchGroup.ALL.name());
        query.setRange(0, 1);
        return singleResult(query.execute(clazz));
    }

    /**
     * Creates a NotificationPublisher object.
     * @param name The name of the NotificationPublisher
     * @return a NotificationPublisher
     */
    public NotificationPublisher createNotificationPublisher(final String name, final String description,
                                                             final Class<? extends Publisher> publisherClass, final String templateContent,
                                                             final String templateMimeType, final boolean defaultPublisher) {
        return callInTransaction(() -> {
            final NotificationPublisher publisher = new NotificationPublisher();
            publisher.setName(name);
            publisher.setDescription(description);
            publisher.setPublisherClass(publisherClass.getName());
            publisher.setTemplate(templateContent);
            publisher.setTemplateMimeType(templateMimeType);
            publisher.setDefaultPublisher(defaultPublisher);
            return pm.makePersistent(publisher);
        });
    }

    /**
     * Updates a NotificationPublisher.
     * @return a NotificationPublisher object
     */
    public NotificationPublisher updateNotificationPublisher(NotificationPublisher transientPublisher) {
        NotificationPublisher publisher = null;
        if (transientPublisher.getId() > 0) {
            publisher = getObjectById(NotificationPublisher.class, transientPublisher.getId());
        } else if (transientPublisher.isDefaultPublisher()) {
            publisher = getDefaultNotificationPublisher(transientPublisher.getPublisherClass());
        }
        if (publisher != null) {
            publisher.setName(transientPublisher.getName());
            publisher.setDescription(transientPublisher.getDescription());
            publisher.setPublisherClass(transientPublisher.getPublisherClass());
            publisher.setTemplate(transientPublisher.getTemplate());
            publisher.setTemplateMimeType(transientPublisher.getTemplateMimeType());
            publisher.setDefaultPublisher(transientPublisher.isDefaultPublisher());
            return persist(publisher);
        }
        return null;
    }

    /**
     * Removes projects from NotificationRules
     */
    @SuppressWarnings("unchecked")
    public void removeProjectFromNotificationRules(final Project project) {
        final Query<NotificationRule> query = pm.newQuery(NotificationRule.class, "projects.contains(:project)");
        for (final NotificationRule rule: (List<NotificationRule>) query.execute(project)) {
            rule.getProjects().remove(project);
            persist(rule);
        }
    }

    /**
     * Removes teams from NotificationRules
     */
    @SuppressWarnings("unchecked")
    public void removeTeamFromNotificationRules(final Team team) {
        final Query<NotificationRule> query = pm.newQuery(NotificationRule.class, "teams.contains(:team)");
        for (final NotificationRule rule: (List<NotificationRule>) query.execute(team)) {
            rule.getTeams().remove(team);
            persist(rule);
        }
    }

    /**
     * Delete a notification publisher and associated rules.
     */
    public void deleteNotificationPublisher(final NotificationPublisher notificationPublisher) {
        final Query<NotificationRule> query = pm.newQuery(NotificationRule.class, "publisher.uuid == :uuid");
        query.deletePersistentAll(notificationPublisher.getUuid());
        delete(notificationPublisher);
    }

    /**
     * @since 4.12.3
     */
    @Override
    public boolean bind(final NotificationRule notificationRule, final Collection<Tag> tags, final boolean keepExisting) {
        assertPersistent(notificationRule, "notificationRule must be persistent");
        assertPersistentAll(tags, "tags must be persistent");

        return callInTransaction(() -> {
            boolean modified = false;

            if (notificationRule.getTags() == null) {
                notificationRule.setTags(new ArrayList<>());
            }

            if (!keepExisting) {
                for (final Tag existingTag : notificationRule.getTags()) {
                    if (!tags.contains(existingTag)) {
                        notificationRule.getTags().remove(existingTag);
                        if (existingTag.getNotificationRules() != null) {
                            existingTag.getNotificationRules().remove(notificationRule);
                        }
                        modified = true;
                    }
                }
            }

            for (final Tag tag : tags) {
                if (!notificationRule.getTags().contains(tag)) {
                    notificationRule.getTags().add(tag);

                    if (tag.getNotificationRules() == null) {
                        tag.setNotificationRules(new ArrayList<>(List.of(notificationRule)));
                    } else if (!tag.getNotificationRules().contains(notificationRule)) {
                        tag.getNotificationRules().add(notificationRule);
                    }

                    modified = true;
                }
            }

            return modified;
        });
    }

    /**
     * @since 4.12.0
     */
    @Override
    public boolean bind(final NotificationRule notificationRule, final Collection<Tag> tags) {
        return bind(notificationRule, tags, /* keepExisting */ false);
    }

    /**
     * @since 4.13.0
     */
    public List<NotificationRule> getDueScheduledNotificationRules() {
        final Query<NotificationRule> query = pm.newQuery(NotificationRule.class);
        query.setFilter("triggerType == :triggerType && scheduleNextTriggerAt < :now && enabled");
        query.setNamedParameters(Map.ofEntries(
                Map.entry("triggerType", NotificationTriggerType.SCHEDULE),
                Map.entry("now", new Date())));
        return executeAndCloseList(query);
    }

    /**
     * @since 4.13.0
     */
    public List<Project> getProjectsForNotificationById(final Collection<Long> ids) {
        final Query<Project> query = pm.newQuery(Project.class);
        query.setFilter(":ids.contains(id)");
        query.setParameters(ids);

        try (var ignored = new ScopedCustomization(pm)
                .withFetchGroup(Project.FetchGroup.NOTIFICATION.name())) {
            return executeAndCloseList(query);
        }
    }

    /**
     * @since 4.13.0
     */
    public List<Component> getComponentsForNotificationById(final Collection<Long> ids) {
        final Query<Component> query = pm.newQuery(Component.class);
        query.setFilter(":ids.contains(id)");
        query.setParameters(ids);

        try (var ignored = new ScopedCustomization(pm)
                .withFetchGroup(Component.FetchGroup.NOTIFICATION.name())) {
            return executeAndCloseList(query);
        }
    }

    /**
     * @since 4.13.0
     */
    public List<PolicyCondition> getPolicyConditionsForNotificationById(final Collection<Long> ids) {
        final Query<PolicyCondition> query = pm.newQuery(PolicyCondition.class);
        query.setFilter(":ids.contains(id)");
        query.setParameters(ids);

        try (var ignored = new ScopedCustomization(pm)
                .withFetchGroup(PolicyCondition.FetchGroup.NOTIFICATION.name())) {
            return executeAndCloseList(query);
        }
    }

    /**
     * @since 4.13.0
     */
    public List<Vulnerability> getVulnerabilitiesForNotificationById(final Collection<Long> ids) {
        final Query<Vulnerability> query = pm.newQuery(Vulnerability.class);
        query.setFilter(":ids.contains(id)");
        query.setParameters(ids);

        try (var ignored = new ScopedCustomization(pm)
                .withFetchGroup(Vulnerability.FetchGroup.NOTIFICATION.name())) {
            return executeAndCloseList(query);
        }
    }

    /**
     * @since 4.13.1
     */
    @Override
    public Set<String> getTeamMemberEmailsForNotificationRule(final long ruleId) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                SELECT "MANAGEDUSER"."EMAIL" AS "EMAIL"
                  FROM "NOTIFICATIONRULE_TEAMS"
                 INNER JOIN "TEAM"
                    ON "TEAM"."ID" = "NOTIFICATIONRULE_TEAMS"."TEAM_ID"
                 INNER JOIN "MANAGEDUSERS_TEAMS"
                    ON "MANAGEDUSERS_TEAMS"."TEAM_ID" = "TEAM"."ID"
                 INNER JOIN "MANAGEDUSER"
                    ON "MANAGEDUSER"."ID" = "MANAGEDUSERS_TEAMS"."MANAGEDUSER_ID"
                 WHERE "NOTIFICATIONRULE_TEAMS"."NOTIFICATIONRULE_ID" = :ruleId
                   AND "MANAGEDUSER"."EMAIL" IS NOT NULL
                 UNION ALL
                SELECT "LDAPUSER"."EMAIL" AS "EMAIL"
                  FROM "NOTIFICATIONRULE_TEAMS"
                 INNER JOIN "TEAM"
                    ON "TEAM"."ID" = "NOTIFICATIONRULE_TEAMS"."TEAM_ID"
                 INNER JOIN "LDAPUSERS_TEAMS"
                    ON "LDAPUSERS_TEAMS"."TEAM_ID" = "TEAM"."ID"
                 INNER JOIN "LDAPUSER"
                    ON "LDAPUSER"."ID" = "LDAPUSERS_TEAMS"."LDAPUSER_ID"
                 WHERE "NOTIFICATIONRULE_TEAMS"."NOTIFICATIONRULE_ID" = :ruleId
                   AND "LDAPUSER"."EMAIL" IS NOT NULL
                 UNION ALL
                SELECT "OIDCUSER"."EMAIL" AS "EMAIL"
                  FROM "NOTIFICATIONRULE_TEAMS"
                 INNER JOIN "TEAM"
                    ON "TEAM"."ID" = "NOTIFICATIONRULE_TEAMS"."TEAM_ID"
                 INNER JOIN "OIDCUSERS_TEAMS"
                    ON "OIDCUSERS_TEAMS"."TEAM_ID" = "TEAM"."ID"
                 INNER JOIN "OIDCUSER"
                    ON "OIDCUSER"."ID" = "OIDCUSERS_TEAMS"."OIDCUSERS_ID"
                 WHERE "NOTIFICATIONRULE_TEAMS"."NOTIFICATIONRULE_ID" = :ruleId
                   AND "OIDCUSER"."EMAIL" IS NOT NULL
                """);
        query.setNamedParameters(Map.of("ruleId", ruleId));

        return new HashSet<>(executeAndCloseResultList(query, String.class));
    }

}
