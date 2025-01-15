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
package org.dependencytrack.model;

import java.util.List;
import java.util.Set;

import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;

import alpine.model.Team;
import alpine.notification.NotificationLevel;

public interface Rule {
    public String getName();
    public boolean isEnabled();
    public boolean isNotifyChildren();
    public boolean isLogSuccessfulPublish();
    public NotificationScope getScope();
    public NotificationLevel getNotificationLevel();
    public NotificationPublisher getPublisher();
    public String getPublisherConfig();
    public Set<NotificationGroup> getNotifyOn();
    public String getMessage();
    public List<Project> getProjects();
    public List<Team> getTeams();
}
