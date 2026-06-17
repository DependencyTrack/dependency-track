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
package org.dependencytrack.policy.cel;

import dev.cel.common.types.CelType;
import dev.cel.common.types.ListType;
import dev.cel.common.types.StructTypeReference;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Tools;
import org.dependencytrack.proto.policy.v1.VersionDistance;
import org.dependencytrack.proto.policy.v1.Vulnerability;

public final class CelPolicyTypes {

    public static final CelType TYPE_COMPONENT = StructTypeReference.create(Component.getDescriptor().getFullName());
    public static final CelType TYPE_COMPONENT_PROPERTY = StructTypeReference.create(Component.Property.getDescriptor().getFullName());
    public static final CelType TYPE_LICENSE = StructTypeReference.create(License.getDescriptor().getFullName());
    public static final CelType TYPE_LICENSE_GROUP = StructTypeReference.create(License.Group.getDescriptor().getFullName());
    public static final CelType TYPE_PROJECT = StructTypeReference.create(Project.getDescriptor().getFullName());
    public static final CelType TYPE_PROJECT_METADATA = StructTypeReference.create(Project.Metadata.getDescriptor().getFullName());
    public static final CelType TYPE_PROJECT_PROPERTY = StructTypeReference.create(Project.Property.getDescriptor().getFullName());
    public static final CelType TYPE_TOOLS = StructTypeReference.create(Tools.getDescriptor().getFullName());
    public static final CelType TYPE_VULNERABILITY = StructTypeReference.create(Vulnerability.getDescriptor().getFullName());
    public static final CelType TYPE_VULNERABILITIES = ListType.create(TYPE_VULNERABILITY);
    public static final CelType TYPE_VULNERABILITY_ALIAS = StructTypeReference.create(Vulnerability.Alias.getDescriptor().getFullName());
    public static final CelType TYPE_VERSION_DISTANCE = StructTypeReference.create(VersionDistance.getDescriptor().getFullName());

    private CelPolicyTypes() {
    }

}
