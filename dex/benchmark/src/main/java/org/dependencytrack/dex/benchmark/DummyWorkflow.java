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
package org.dependencytrack.dex.benchmark;

import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ActivityHandle;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.jspecify.annotations.Nullable;

@WorkflowSpec(name = "dummy")
public class DummyWorkflow implements Workflow<Void, Void> {

    @Override
    public @Nullable Void execute(
            WorkflowContext<@Nullable Void> ctx,
            @Nullable Void argument) {
        final ActivityHandle<Void, Void> dummyActivity = ctx.activity(DummyActivity.class);

        dummyActivity.call(new ActivityCallOptions<Void>().withTaskQueueName("foo")).await();
        dummyActivity.call(new ActivityCallOptions<Void>().withTaskQueueName("bar")).await();
        dummyActivity.call(new ActivityCallOptions<Void>().withTaskQueueName("baz")).await();

        return null;
    }

}
