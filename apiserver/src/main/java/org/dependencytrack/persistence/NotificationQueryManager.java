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

import alpine.persistence.PaginatedResult;
import alpine.persistence.ScopedCustomization;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.model.Tag;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.proto.v1.Notification;
import org.jspecify.annotations.NonNull;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import static org.datanucleus.PropertyNames.PROPERTY_QUERY_SQL_ALLOWALL;
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
    @Override
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
            String name,
            NotificationScope scope,
            NotificationLevel level,
            NotificationPublisher publisher) {
        return callInTransaction(() -> {
            final var rule = new NotificationRule();
            rule.setName(name);
            rule.setScope(scope);
            rule.setNotificationLevel(level);
            rule.setPublisher(publisher);
            rule.setTriggerType(NotificationTriggerType.SCHEDULE);
            rule.setEnabled(false);
            rule.setLogSuccessfulPublish(false);
            rule.setScheduleCron("0 * * * *");
            rule.setScheduleLastTriggeredAt(new Date());
            rule.setScheduleSkipUnchanged(false);
            rule.updateScheduleNextTriggerAt();
            return persist(rule);
        });
    }

    /**
     * Updated an existing NotificationRule.
     * @param transientRule the rule to update
     * @return a NotificationRule
     */
    @Override
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
            rule.setFilterExpression(transientRule.getFilterExpression());
            rule.setNotifyOn(transientRule.getNotifyOn());
            bind(rule, resolveTags(transientRule.getTags()));
            return rule;
        });
    }

    /**
     * Returns a paginated list of all notification rules.
     * @return a paginated list of NotificationRules
     */
    @Override
    public PaginatedResult getNotificationRules(NotificationTriggerType triggerTypeFilter) {
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
    @Override
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
    @Override
    public NotificationPublisher getNotificationPublisher(final String name) {
        final Query<NotificationPublisher> query = pm.newQuery(NotificationPublisher.class, "name == :name");
        query.setRange(0, 1);
        return singleResult(query.execute(name));
    }

    /**
     * Retrieves a DefaultNotificationPublisher by its name.
     * @param name The name of the DefaultNotificationPublisher
     * @return a DefaultNotificationPublisher
     */
    @Override
    public NotificationPublisher getDefaultNotificationPublisherByName(final String name) {
        final Query<NotificationPublisher> query = pm.newQuery(NotificationPublisher.class, "name == :name && defaultPublisher == true");
        query.getFetchPlan().addGroup(NotificationPublisher.FetchGroup.ALL.name());
        query.setRange(0, 1);
        return singleResult(query.execute(name));
    }

    /**
     * Creates a NotificationPublisher object.
     * @param name The name of the NotificationPublisher
     * @return a NotificationPublisher
     */
    @Override
    public NotificationPublisher createNotificationPublisher(
            @NonNull String name,
            String description,
            @NonNull String extensionName,
            String templateContent,
            String templateMimeType,
            boolean defaultPublisher) {
        return callInTransaction(() -> {
            final NotificationPublisher publisher = new NotificationPublisher();
            publisher.setName(name);
            publisher.setDescription(description);
            publisher.setExtensionName(extensionName);
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
    @Override
    public NotificationPublisher updateNotificationPublisher(NotificationPublisher transientPublisher) {
        final var publisher = getObjectById(NotificationPublisher.class, transientPublisher.getId());
        if (publisher != null) {
            publisher.setName(transientPublisher.getName());
            publisher.setDescription(transientPublisher.getDescription());
            publisher.setExtensionName(transientPublisher.getExtensionName());
            publisher.setTemplate(transientPublisher.getTemplate());
            publisher.setTemplateMimeType(transientPublisher.getTemplateMimeType());
            publisher.setDefaultPublisher(transientPublisher.isDefaultPublisher());
            return persist(publisher);
        }
        return null;
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
                notificationRule.setTags(new HashSet<>());
            }

            if (!keepExisting) {
                final Iterator<Tag> existingTagsIterator = notificationRule.getTags().iterator();
                while (existingTagsIterator.hasNext()) {
                    final Tag existingTag = existingTagsIterator.next();
                    if (!tags.contains(existingTag)) {
                        existingTagsIterator.remove();
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
                        tag.setNotificationRules(new HashSet<>(Set.of(notificationRule)));
                    } else {
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
     * @return All notifications in the notification outbox.
     * @since 5.0.0
     */
    @Override
    public List<Notification> getNotificationOutbox() {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                SELECT "PAYLOAD"
                  FROM "NOTIFICATION_OUTBOX"
                 ORDER BY "ID"
                """);

        return executeAndCloseResultList(query, byte[].class).stream()
                .map(data -> {
                    try {
                        return Notification.parseFrom(data);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                })
                .toList();
    }

    /**
     * @since 5.0.0
     */
    @Override
    public void truncateNotificationOutbox() {
        try (var _ = new ScopedCustomization(pm).withProperty(PROPERTY_QUERY_SQL_ALLOWALL, "true")) {
            final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                TRUNCATE TABLE "NOTIFICATION_OUTBOX"
                """);
            executeAndClose(query);
        }
    }

}
