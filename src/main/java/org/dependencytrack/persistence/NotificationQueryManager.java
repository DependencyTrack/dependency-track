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

import alpine.notification.NotificationLevel;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.Publisher;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.List;

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
        final NotificationRule rule = new NotificationRule();
        rule.setName(name);
        rule.setScope(scope);
        rule.setNotificationLevel(level);
        rule.setPublisher(publisher);
        rule.setEnabled(true);
        return persist(rule);
    }

    /**
     * Updated an existing NotificationRule.
     * @param transientRule the rule to update
     * @return a NotificationRule
     */
    public NotificationRule updateNotificationRule(NotificationRule transientRule) {
        final NotificationRule rule = getObjectByUuid(NotificationRule.class, transientRule.getUuid());
        rule.setName(transientRule.getName());
        rule.setNotificationLevel(transientRule.getNotificationLevel());
        rule.setPublisherConfig(transientRule.getPublisherConfig());
        rule.setNotifyOn(transientRule.getNotifyOn());
        return persist(rule);
    }

    /**
     * Returns a paginated list of all notification rules.
     * @return a paginated list of NotificationRules
     */
    public PaginatedResult getNotificationRules() {
        final Query<NotificationRule> query = pm.newQuery(NotificationRule.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:name) || publisher.name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
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
        return singleResult(query.execute(name));
    }

    /**
     * Retrieves a NotificationPublisher by its class.
     * @param clazz The Class of the NotificationPublisher
     * @return a NotificationPublisher
     */
    NotificationPublisher getDefaultNotificationPublisher(final Class<Publisher> clazz) {
        return getDefaultNotificationPublisher(clazz.getCanonicalName());
    }

    /**
     * Retrieves a NotificationPublisher by its class.
     * @param clazz The Class of the NotificationPublisher
     * @return a NotificationPublisher
     */
    private NotificationPublisher getDefaultNotificationPublisher(final String clazz) {
        final Query<NotificationPublisher> query = pm.newQuery(NotificationPublisher.class, "publisherClass == :publisherClass && defaultPublisher == true");
        return singleResult(query.execute(clazz));
    }

    /**
     * Creates a NotificationPublisher object.
     * @param name The name of the NotificationPublisher
     * @return a NotificationPublisher
     */
    public NotificationPublisher createNotificationPublisher(final String name, final String description,
                                                             final Class<Publisher> publisherClass, final String templateContent,
                                                             final String templateMimeType, final boolean defaultPublisher) {
        pm.currentTransaction().begin();
        final NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName(name);
        publisher.setDescription(description);
        publisher.setPublisherClass(publisherClass.getCanonicalName());
        publisher.setTemplate(templateContent);
        publisher.setTemplateMimeType(templateMimeType);
        publisher.setDefaultPublisher(defaultPublisher);
        pm.makePersistent(publisher);
        pm.currentTransaction().commit();
        return getObjectById(NotificationPublisher.class, publisher.getId());
    }

    /**
     * Updates a NotificationPublisher.
     * @return a NotificationPublisher object
     */
    NotificationPublisher updateNotificationPublisher(NotificationPublisher transientPublisher) {
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
}
