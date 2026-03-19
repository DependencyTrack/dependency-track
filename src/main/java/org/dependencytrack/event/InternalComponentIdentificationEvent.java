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

import alpine.event.framework.SingletonCapableEvent;

import java.util.UUID;

/**
 * Defines an event triggered when internal components should be identified in the entire portfolio.
 *
 * @author nscuro
 * @since 3.7.0
 */
public class InternalComponentIdentificationEvent extends SingletonCapableEvent {

    private static final UUID CHAIN_IDENTIFIER = UUID.fromString("57096d18-fdad-41c7-a59e-925ce7dc3d0e");

    public InternalComponentIdentificationEvent() {
        setChainIdentifier(CHAIN_IDENTIFIER);
        setSingleton(true);
    }

}
