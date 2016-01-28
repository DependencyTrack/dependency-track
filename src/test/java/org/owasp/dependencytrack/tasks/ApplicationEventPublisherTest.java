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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.dependencytrack.config.EventConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.concurrent.*;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

/**
 * Created by Jason Wraxall on 25/01/16.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes={ApplicationEventPublisherTest.Context.class, EventConfiguration.class})
public class ApplicationEventPublisherTest {

    @Autowired
    ApplicationEventMulticaster applicationEventMulticaster;

    @Test
    public void shouldPublishEventsAsynchronously(){

        boolean completedSuccessfully = false;
        Executor executor = Executors.newSingleThreadExecutor();
        FutureTask<Boolean> future = new FutureTask<>(new ThreadedTestTask(applicationEventMulticaster));
        executor.execute(future);
        try {
            completedSuccessfully = future.get(2, TimeUnit.SECONDS);
        }catch(TimeoutException te){
          fail("Task took too long");
        }
        catch (Exception e) {
        }
        assertThat(completedSuccessfully,is(true));
    }

    public static class ThreadedTestTask implements Callable<Boolean>{

        boolean wasCompleted = false;
        private ApplicationEventMulticaster applicationEventMulticaster;

        public ThreadedTestTask(ApplicationEventMulticaster applicationEventMulticaster){

            this.applicationEventMulticaster = applicationEventMulticaster;
        }

        @Override
        public Boolean call() throws Exception {
            applicationEventMulticaster.multicastEvent(new TestEvent(this));
            System.out.println("in threaded task");
            return true;
        }

    }

    public static class TestEvent extends ApplicationEvent {
        /**
         * Create a new ApplicationEvent.
         *
         * @param source the object on which the event initially occurred (never {@code null})
         */
        public TestEvent(Object source) {
            super(source);
        }
    }

    public static class TestListener   implements ApplicationListener<TestEvent> {

        @Override
        public void onApplicationEvent(TestEvent event) {
            try {
                System.out.println("App Event Started");
                Thread.sleep(5000L); // simulate a long task
                System.out.println("App Event Ended");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public static class Context {

        @Bean
        TestListener testListener(){
            return new TestListener();
        }
    }
}
