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
package org.dependencytrack.event;

import java.util.UUID;

import alpine.event.framework.SingletonCapableEvent;

/**
 * Defines an event used to start a mirror of the NVD.
 *
 * @author Valentijn Scholten
 * @since 4.13.0
 */
public class ComposerAdvisoryMirrorEvent extends SingletonCapableEvent {

    private static final UUID CHAIN_IDENTIFIER = UUID.fromString("62710465-3117-4cc1-ad9a-d1dce721aa86");

    public ComposerAdvisoryMirrorEvent() {
        setChainIdentifier(CHAIN_IDENTIFIER);
        setSingleton(true);
    }

}
