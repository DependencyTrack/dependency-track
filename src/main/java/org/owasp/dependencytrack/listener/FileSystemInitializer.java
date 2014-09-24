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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */

package org.owasp.dependencytrack.listener;

import org.owasp.dependencytrack.Constants;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import java.io.File;

@Component
public class FileSystemInitializer implements ApplicationListener<ContextRefreshedEvent> {

    /**
     * Method is called when the application context is started or refreshed.
     *
     * @param event A ContextRefreshedEvent
     */
    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        makeDirectory(new File(Constants.APP_DIR));
        makeDirectory(new File(Constants.DATA_DIR));
        makeDirectory(new File(Constants.NIST_DIR));
        makeDirectory(new File(Constants.LOG_DIR));
    }

    private void makeDirectory(File file) {
        if (!file.exists()) {
            System.out.println("Creating directory: " + file.getAbsolutePath());
            if (!file.mkdir()) {
                System.out.println("An error occurred creating directory: " + file.getAbsolutePath());
            }
        }
    }

}
