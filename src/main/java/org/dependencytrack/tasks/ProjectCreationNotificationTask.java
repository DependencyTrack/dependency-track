package org.dependencytrack.tasks;

import org.dependencytrack.event.ProjectCreationEvent;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;

/**
 * Subscriber task that sends a notification when a new project is created.
 *
 * @author Mark Zeman
 * @since 4.6.x
 */
public class ProjectCreationNotificationTask implements Subscriber{

    private static final Logger LOGGER = Logger.getLogger(ProjectCreationNotificationTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e){
      if (e instanceof ProjectCreationEvent){
        LOGGER.info("A new project has been created. Dispatching notification for it.");
        final ProjectCreationEvent event = (ProjectCreationEvent) e;
        Notification.dispatch(new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.NEW_PROJECT)
                .title(NotificationConstants.Title.NEW_PROJECT)
                .level(NotificationLevel.INFORMATIONAL)
                .content(event.getProjectName() + " was created"));
      }
    }
    
}
