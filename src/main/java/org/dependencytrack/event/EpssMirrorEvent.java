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
 * Defines an event used to start a mirror of EPSS.
 *
 * @author Steve Springett
 * @since 4.5.0
 */
public class EpssMirrorEvent extends SingletonCapableEvent {

    private static final UUID CHAIN_IDENTIFIER = UUID.fromString("63aa687a-17f0-4e2d-abd3-e2016b3c4f0a");

    public EpssMirrorEvent() {
        setChainIdentifier(CHAIN_IDENTIFIER);
        setSingleton(true);
    }

}
