/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.tasks;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Created by Jason Wraxall on 21/12/15.
 */
@Component
public class ScheduledTasks  implements ApplicationEventPublisherAware, ApplicationListener<ContextRefreshedEvent>{

    /**
     * Event publisher
     */
    private ApplicationEventPublisher applicationEventPublisher;

    @Scheduled( cron = "0 0 2 * * *") // every day at 2am
    public void doRegularTasks(){
        applicationEventPublisher.publishEvent(new NistDataMirrorUpdateRequestedEvent(this));
        applicationEventPublisher.publishEvent(new DependencyCheckAnalysisRequestEvent(this));
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        doRegularTasks();
    }

}
