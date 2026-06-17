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
package org.dependencytrack.support.datanucleus.valuegenerator;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedEpochRandomGenerator;
import org.datanucleus.store.StoreManager;
import org.datanucleus.store.valuegenerator.AbstractGenerator;
import org.datanucleus.store.valuegenerator.ValueGenerationBlock;

import java.util.Properties;

public class UUIDv7Generator extends AbstractGenerator<String> {

    private final TimeBasedEpochRandomGenerator generator;

    public UUIDv7Generator(final StoreManager storeMgr, final String name, final Properties ignored) {
        super(storeMgr, name);
        this.generator = Generators.timeBasedEpochRandomGenerator();
    }

    @Override
    protected ValueGenerationBlock<String> reserveBlock(final long size) {
        final var ids = new String[(int) size];
        for (int i = 0; i < size; i++) {
            ids[i] = generator.generate().toString();
        }

        return new ValueGenerationBlock<>(ids);
    }

}
