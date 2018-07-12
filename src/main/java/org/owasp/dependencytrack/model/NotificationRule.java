/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

package org.owasp.dependencytrack.model;

import alpine.notification.NotificationLevel;
import alpine.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.owasp.dependencytrack.notification.NotificationConstants;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Defines a Model class for notification configurations.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class NotificationRule implements Serializable {

    private static final long serialVersionUID = 2534439091019367263L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    /**
     * The String representation of the name of the notification.
     */
    @Persistent
    @Column(name = "NAME", allowsNull = "false")
    @NotNull
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    @Persistent
    @Column(name = "ENABLED")
    private boolean enabled;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "SCOPE", allowsNull = "false")
    @NotNull
    private String scope;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "NOTIFICATION_LEVEL", jdbcType = "VARCHAR")
    private NotificationLevel notificationLevel;

    @Persistent(table = "NOTIFICATIONRULE_PROJECTS", defaultFetchGroup = "true")
    @Join(column = "NOTIFICATIONRULE_ID")
    @Element(column = "PROJECT_ID")
    private List<Project> projects;

    @Persistent
    @Column(name = "NOTIFY_ON", length = 1024)
    private String notifyOn;

    @Persistent
    @Column(name = "MESSAGE", length = 1024)
    @Size(max = 1024)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The message may only contain printable characters")
    private String message;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PUBLISHER")
    private NotificationPublisher publisher;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PUBLISHER_CONFIG", jdbcType = "CLOB")
    private String publisherConfig;


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public NotificationLevel getNotificationLevel() {
        return notificationLevel;
    }

    public void setNotificationType(NotificationLevel notificationLevel) {
        this.notificationLevel = notificationLevel;
    }

    public List<Project> getProjects() {
        return projects;
    }

    public void setProjects(List<Project> projects) {
        this.projects = projects;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public List<NotificationConstants.Group> getNotifyOn() {
        List<NotificationConstants.Group> result = new ArrayList<>();
        if (notifyOn != null) {
            String[] groups = notifyOn.split(",");
            for (String s: groups) {
                result.add(NotificationConstants.Group.valueOf(s));
            }
        }
        return result;
    }

    public void setNotifyOn(List<NotificationConstants.Group> groups) {
        StringBuilder sb = new StringBuilder();
        for (int i=0; i<groups.size(); i++) {
            sb.append(groups.get(i));
            if (i+1 < groups.size()) {
                sb.append(",");
            }
        }
        this.notifyOn = sb.toString();
    }

    public NotificationPublisher getNotificationPublisher() {
        return publisher;
    }

    public void setNotificationPublisher(NotificationPublisher publisher) {
        this.publisher = publisher;
    }

    public String getPublisherConfig() {
        return publisherConfig;
    }

    public void setPublisherConfig(String publisherConfig) {
        this.publisherConfig = publisherConfig;
    }
}
