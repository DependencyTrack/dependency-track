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
        applicationEventPublisher.publishEvent(new VulnerabilityScanRequestedEvent(this));
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
