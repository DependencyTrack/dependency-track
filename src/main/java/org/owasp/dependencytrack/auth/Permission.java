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
package org.owasp.dependencytrack.auth;

import alpine.auth.AlpinePermission;

/**
 * Defines permissions specific to Dependency-Track.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class Permission extends AlpinePermission {

    public static final String SCAN_UPLOAD = "SCAN_UPLOAD";
    public static final String PROJECT_MANAGE = "PROJECT_MANAGE";
    public static final String PROJECT_VIEW = "PROJECT_VIEW";

    public static final String COMPONENT_VIEW = "COMPONENT_VIEW";
    public static final String COMPONENT_MANAGE = "COMPONENT_MANAGE";

}
