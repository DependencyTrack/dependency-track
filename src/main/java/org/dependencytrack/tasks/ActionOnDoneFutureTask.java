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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import java.util.concurrent.FutureTask;

import alpine.common.logging.Logger;

public class ActionOnDoneFutureTask extends FutureTask<Void> {
    private static final Logger LOGGER = Logger.getLogger(ActionOnDoneFutureTask.class);
    private final Runnable action;

    public ActionOnDoneFutureTask(Runnable runnable, Runnable actionOnDone) {
        super(runnable, null);
        this.action = actionOnDone;
    }

    @Override
    protected void done() {
        super.done();
        try {
            this.action.run();
        } catch (Exception e) {
            // just catch and log, do not interfere with completion
            LOGGER.warn(e.toString());
        }
    }
}
