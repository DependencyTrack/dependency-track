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
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.model.Tag;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationScope;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;
import static org.dependencytrack.util.PersistenceUtil.assertPersistentAll;

public class NotificationQueryManager extends QueryManager {

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
    public NotificationRule createNotificationRule(
            String name, NotificationScope scope, NotificationLevel level, NotificationPublisher publisher) {
        final var rule = new NotificationRule();
        rule.setTriggerType(NotificationTriggerType.EVENT);
        rule.setName(name);
        rule.setScope(scope);
        rule.setNotificationLevel(level);
        rule.setPublisher(publisher);
        rule.setEnabled(true);
        rule.setNotifyChildren(true);
        rule.setLogSuccessfulPublish(false);
        return createNotificationRule(rule);
    }

    /**
     * Creates a new {@link NotificationRule} from a transient rule.
     * The trigger type decides which groups are allowed and whether schedule fields apply.
     *
     * @throws IllegalArgumentException if {@code notifyOn} has groups not supported for the trigger type
     * @since 5.3.0
     */
    @Override
    public NotificationRule createNotificationRule(final NotificationRule transientRule) {
        final NotificationTriggerType triggerType =
                requireNonNull(transientRule.getTriggerType(), "triggerType must not be null");

        return callInTransaction(() -> {
            final Set<NotificationGroup> notifyOn = validateNotifyOn(triggerType, transientRule.getNotifyOn());

            final var rule = new NotificationRule();
            rule.setTriggerType(triggerType);
            rule.setName(transientRule.getName());
            rule.setScope(transientRule.getScope());
            rule.setNotificationLevel(transientRule.getNotificationLevel());
            rule.setPublisher(transientRule.getPublisher());
            rule.setEnabled(transientRule.isEnabled());
            rule.setNotifyChildren(transientRule.isNotifyChildren());
            rule.setLogSuccessfulPublish(transientRule.isLogSuccessfulPublish());
            rule.setNotifyOn(notifyOn);
            rule.setPublisherConfig(transientRule.getPublisherConfig());
            rule.setFilterExpression(transientRule.getFilterExpression());

            if (triggerType == NotificationTriggerType.SCHEDULE) {
                rule.setScheduleCron(transientRule.getScheduleCron());
                rule.setScheduleSkipUnchanged(transientRule.isScheduleSkipUnchanged());
                rule.setScheduleLastTriggeredAt(new Date());
                rule.updateScheduleNextTriggerAt();
            }

            final NotificationRule persistedRule = persist(rule);

            // Tags can only be bound once the rule is persisted.
            if (transientRule.getTags() != null && !transientRule.getTags().isEmpty()) {
                bind(persistedRule, resolveTags(transientRule.getTags()));
            }

            return persistedRule;
        });
    }

    /**
     * @since 4.13.0
     */
    @Override
    public NotificationRule createScheduledNotificationRule(
            String name, NotificationScope scope, NotificationLevel level, NotificationPublisher publisher) {
        final var rule = new NotificationRule();
        rule.setTriggerType(NotificationTriggerType.SCHEDULE);
        rule.setName(name);
        rule.setScope(scope);
        rule.setNotificationLevel(level);
        rule.setPublisher(publisher);
        rule.setEnabled(false);
        rule.setLogSuccessfulPublish(false);
        rule.setScheduleCron("0 * * * *");
        rule.setScheduleSkipUnchanged(false);
        return createNotificationRule(rule);
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
            if (transientRule.getTriggerType() != null && rule.getTriggerType() != transientRule.getTriggerType()) {
                throw new IllegalArgumentException("Trigger type can not be changed");
            }

            final Set<NotificationGroup> notifyOn =
                    validateNotifyOn(rule.getTriggerType(), transientRule.getNotifyOn());

            if (rule.getTriggerType() == NotificationTriggerType.SCHEDULE) {
                rule.setScheduleCron(transientRule.getScheduleCron());
                rule.setScheduleSkipUnchanged(transientRule.isScheduleSkipUnchanged());
                rule.updateScheduleNextTriggerAt();
            }

            rule.setName(transientRule.getName());
            rule.setEnabled(transientRule.isEnabled());
            rule.setNotifyChildren(transientRule.isNotifyChildren());
            rule.setLogSuccessfulPublish(transientRule.isLogSuccessfulPublish());
            rule.setNotificationLevel(transientRule.getNotificationLevel());
            rule.setPublisherConfig(transientRule.getPublisherConfig());
            rule.setFilterExpression(transientRule.getFilterExpression());
            rule.setNotifyOn(notifyOn);
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
            filterParams.put("name", ".*" + filter.toLowerCase(Locale.ROOT) + ".*");
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
        return (List<NotificationPublisher>) query.execute();
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
     * @since 4.12.3
     */
    @Override
    public boolean bind(
            final NotificationRule notificationRule, final Collection<Tag> tags, final boolean keepExisting) {
        assertPersistent(notificationRule, "notificationRule must be persistent");
        assertPersistentAll(tags, "tags must be persistent");

        return callInTransaction(() -> {
            boolean modified = false;

            if (notificationRule.getTags() == null) {
                notificationRule.setTags(new HashSet<>());
            }

            if (!keepExisting) {
                final Iterator<Tag> existingTagsIterator =
                        notificationRule.getTags().iterator();
                while (existingTagsIterator.hasNext()) {
                    final Tag existingTag = existingTagsIterator.next();
                    if (!tags.contains(existingTag)) {
                        existingTagsIterator.remove();
                        modified = true;
                    }
                }
            }
            for (final Tag tag : tags) {
                if (!notificationRule.getTags().contains(tag)) {
                    notificationRule.getTags().add(tag);
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
     * @return {@code notifyOn}, or an empty set if {@code null}
     * @throws IllegalArgumentException if a group is not supported for {@code triggerType}
     */
    private static Set<NotificationGroup> validateNotifyOn(
            final NotificationTriggerType triggerType, final @Nullable Set<NotificationGroup> notifyOn) {
        final Set<NotificationGroup> groups = requireNonNullElse(notifyOn, Set.of());
        final List<NotificationGroup> invalidGroups = groups.stream()
                .filter(group -> group.getSupportedTriggerType() != triggerType)
                .toList();
        if (!invalidGroups.isEmpty()) {
            throw new IllegalArgumentException(
                    "Groups %s are not supported for trigger type %s".formatted(invalidGroups, triggerType));
        }

        return groups;
    }
}
