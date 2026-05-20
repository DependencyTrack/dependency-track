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
package org.dependencytrack.capabilities;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.api.ServiceLocator;
import org.glassfish.hk2.utilities.binding.AbstractBinder;

/**
 * @since 5.0.0
 */
public final class SystemCapabilitiesBinder extends AbstractBinder {

    @Override
    protected void configure() {
        bindFactory(SystemCapabilitiesAggregatorFactory.class)
                .to(SystemCapabilitiesAggregator.class)
                .in(Singleton.class);
    }

    private static final class SystemCapabilitiesAggregatorFactory implements Factory<SystemCapabilitiesAggregator> {

        private final ServiceLocator serviceLocator;

        @Inject
        private SystemCapabilitiesAggregatorFactory(ServiceLocator serviceLocator) {
            this.serviceLocator = serviceLocator;
        }

        @Override
        public SystemCapabilitiesAggregator provide() {
            return new SystemCapabilitiesAggregator(serviceLocator);
        }

        @Override
        public void dispose(final SystemCapabilitiesAggregator instance) {
        }

    }

}
