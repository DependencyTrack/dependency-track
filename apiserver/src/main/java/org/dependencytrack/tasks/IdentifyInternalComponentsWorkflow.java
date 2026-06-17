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

import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.jspecify.annotations.Nullable;

/**
 * @since 5.0.0
 */
@WorkflowSpec(name = "identify-internal-components")
public final class IdentifyInternalComponentsWorkflow implements Workflow<Void, Void> {

    public static final String INSTANCE_ID = "identify-internal-components";

    @Override
    public @Nullable Void execute(WorkflowContext<Void> ctx, @Nullable Void arg) throws Exception {
        ctx.activity(IdentifyInternalComponentsActivity.class).call().await();
        return null;
    }

}
