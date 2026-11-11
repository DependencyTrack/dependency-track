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

import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.persistence.jdbi.BomDao;
import org.dependencytrack.proto.internal.workflow.v1.IsOriginalBomFileReferencedArg;
import org.dependencytrack.proto.internal.workflow.v1.IsOriginalBomFileReferencedRes;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.3.0
 */
@NullMarked
@ActivitySpec(name = "is-original-bom-file-referenced")
public final class IsOriginalBomFileReferencedActivity
        implements Activity<IsOriginalBomFileReferencedArg, IsOriginalBomFileReferencedRes> {

    @Override
    public IsOriginalBomFileReferencedRes execute(ActivityContext ctx, @Nullable IsOriginalBomFileReferencedArg arg) {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final UUID projectUuid = UUID.fromString(arg.getProjectUuid());
        final byte[] fileMetadata = arg.getBomFileMetadata().toByteArray();

        final boolean referenced = withJdbiHandle(
                handle -> handle.attach(BomDao.class).isOriginalFileReferenced(projectUuid, fileMetadata));

        return IsOriginalBomFileReferencedRes.newBuilder()
                .setReferenced(referenced)
                .build();
    }
}
