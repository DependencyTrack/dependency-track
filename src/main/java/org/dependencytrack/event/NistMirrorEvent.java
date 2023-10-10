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
package org.dependencytrack.event;

import alpine.event.framework.SingletonCapableEvent;

import java.util.UUID;

/**
 * Defines an event used to start a mirror of the NVD.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class NistMirrorEvent extends SingletonCapableEvent {

    private static final UUID CHAIN_IDENTIFIER = UUID.fromString("077fa5fe-2f7a-457f-a0f1-9e9a0e578ede");

    public NistMirrorEvent() {
        setChainIdentifier(CHAIN_IDENTIFIER);
        setSingleton(true);
    }

}
