/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.servlets;

import alpine.logging.Logger;
import alpine.servlets.FileSystemResourceServlet;
import org.dependencytrack.tasks.NistMirrorTask;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

public class NvdMirrorServlet extends FileSystemResourceServlet {

    private static final Logger LOGGER = Logger.getLogger(NvdMirrorServlet.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(final ServletConfig config) throws ServletException {
        LOGGER.info("Initializing NVD mirror");
        super.init(config);
        super.setDirectory(NistMirrorTask.NVD_MIRROR_DIR);
        super.setAbsolute(true);
    }

}
