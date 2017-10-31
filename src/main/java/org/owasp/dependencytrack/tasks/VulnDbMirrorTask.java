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
package org.owasp.dependencytrack.tasks;

import alpine.Config;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.logging.Logger;
import org.owasp.dependencytrack.event.VulnDbMirrorEvent;
import us.springett.vulndbdatamirror.parser.VulnDbParser;
import us.springett.vulndbdatamirror.parser.model.Results;
import java.io.File;
import java.io.IOException;

/**
 * Subscriber task that performs mirror synchronization of VulnDB.
 * This task relies on an existing mirror generated from vulndb-data-mirror. The mirror must exist
 * in a 'vulndb' subdirectory of the Dependency-Track data directory. i.e.  ~/dependency-track/vulndb
 *
 * https://github.com/stevespringett/vulndb-data-mirror
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class VulnDbMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(VulnDbMirrorTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof VulnDbMirrorEvent) {
            LOGGER.info("Starting VulnDB mirror synchronization task");
            final File vulndbDir = new File(Config.getInstance().getDataDirectorty(), "vulndb");
            if (!vulndbDir.exists()) {
                LOGGER.info("VulnDB mirror directory does not exist. Skipping.");
                return;
            }
            File[] files = vulndbDir.listFiles(
                    (dir, name) -> name.toLowerCase().startsWith("vulnerabilities_")
            );
            for (File file: files) {
                VulnDbParser parser = new VulnDbParser();
                try {
                    Results results = parser.parse(file, us.springett.vulndbdatamirror.parser.model.Vulnerability.class);
                    // todo: map vulnDb vulnerabiliy object to ODT vulnerability object and synchronize.
                } catch (IOException ex) {
                    LOGGER.error("Error occurred parsing VulnDB payload: " + file.getName(), ex);
                }
            }
            LOGGER.info("VulnDB mirror synchronization task complete");
        }
    }

}
