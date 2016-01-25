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

import org.owasp.dependencytrack.tasks.dependencycheck.DependencyCheckAnalysis;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Created by Jason Wraxall on 25/11/15.
 */
@Configuration
public class AllTasks {

    @Value("${app.nist.dir}")
    private String nistDir;

    @Bean
    public NistDataMirrorUpdater nistDataMirrorUpdater() {
        return new NistDataMirrorUpdater(nistDir);
    }

    @Bean
    public DependencyCheckAnalysis dependencyCheckAnalysis(){
        return new DependencyCheckAnalysis();
    }

    @Bean
    public ScheduledTasks scheduledTasks(){
        return new ScheduledTasks();
    }
}
