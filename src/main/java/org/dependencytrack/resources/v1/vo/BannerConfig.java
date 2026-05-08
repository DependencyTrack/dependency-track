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
package org.dependencytrack.resources.v1.vo;

public class BannerConfig {
    public boolean activateBanner;
    public boolean makeBannerDismissable;
    public String message;
    public String colorScheme;
    public boolean customMode;
    public String html;

    public BannerConfig() {
    }

    public BannerConfig(boolean activateBanner, boolean makeBannerDismissable, String message, String colorScheme,
            boolean customMode, String html) {
        this.activateBanner = activateBanner;
        this.makeBannerDismissable = makeBannerDismissable;
        this.message = message;
        this.colorScheme = colorScheme;
        this.customMode = customMode;
        this.html = html;
    }

}
