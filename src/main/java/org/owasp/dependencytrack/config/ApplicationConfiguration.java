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
package org.owasp.dependencytrack.config;

import org.owasp.dependencytrack.service.VulnerabilityServiceImpl;
import org.owasp.dependencytrack.tasks.NistDataMirrorUpdater;
import org.owasp.dependencytrack.tasks.VulnerabilityScanTask;
import org.owasp.dependencytrack.tasks.dependencycheck.DependencyCheckAnalysis;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.context.event.SimpleApplicationEventMulticaster;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Created by jason on 16/11/15.
 */
@Configuration
@Import({DatabaseConfiguration.class,PropertyConfiguration.class})
@EnableAspectJAutoProxy
@EnableAsync
public class ApplicationConfiguration {

    //    <!-- Dependency-Check scan agent scheduler -->
    @Bean
    public VulnerabilityScanTask vulnerabilityScanTask(DependencyCheckAnalysis dependencyCheckAnalysis, VulnerabilityServiceImpl vulnerabilityService){
        VulnerabilityScanTask vulnerabilityScanTask = new VulnerabilityScanTask();
        vulnerabilityScanTask.setDependencyCheckAnalysis(dependencyCheckAnalysis);
        vulnerabilityScanTask.setVulerabilityService(vulnerabilityService);
        return vulnerabilityScanTask;
    }

    @Value("${app.nist.dir}")
    private String nistDir;

    @Bean
    public NistDataMirrorUpdater nistDataMirrorUpdater() {
        return new NistDataMirrorUpdater(nistDir);
    }

    @Bean(name = "properties")
    public PropertiesFactoryBean properties() {
        PropertiesFactoryBean bean = new PropertiesFactoryBean();
        bean.setLocation(new ClassPathResource("application.properties"));
        return bean;
    }


    @Bean
    public ApplicationEventMulticaster applicationEventMulticaster() {
        SimpleApplicationEventMulticaster simpleApplicationEventMulticaster = new SimpleApplicationEventMulticaster();
        simpleApplicationEventMulticaster.setTaskExecutor(new SimpleAsyncTaskExecutor());
        return simpleApplicationEventMulticaster;
    }




}
