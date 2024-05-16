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
