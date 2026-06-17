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

import org.jspecify.annotations.NullMarked;

@NullMarked
@SuppressWarnings("requires-automatic")
module org.dependencytrack.dex.api {
    exports org.dependencytrack.dex.api;
    exports org.dependencytrack.dex.api.failure;
    exports org.dependencytrack.dex.api.payload;
    exports org.dependencytrack.dex.proto.common.v1;
    exports org.dependencytrack.dex.proto.event.v1;
    exports org.dependencytrack.dex.proto.failure.v1;
    exports org.dependencytrack.dex.proto.payload.v1;

    requires com.google.protobuf.util;
    requires transitive com.google.protobuf;
    requires transitive org.jspecify;
    requires transitive org.slf4j;
}