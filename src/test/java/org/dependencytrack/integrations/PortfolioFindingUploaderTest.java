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
package org.dependencytrack.integrations;

import org.junit.Assert;
import org.junit.Test;
import java.io.IOException;
import java.io.InputStream;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PortfolioFindingUploaderTest {

    @Test
    public final void portfolioFindingMethodsTest() throws IOException {
        PortfolioFindingUploader uploader = mock(PortfolioFindingUploader.class);
        when(uploader.process()).thenReturn(new InputStream() {
            @Override
            public int read() throws IOException {
                return 1;
            }
            @Override
            public int available() throws IOException {
                return 1;
            }
        });
        InputStream in = uploader.process();
        Assert.assertTrue(in != null && in.available() == 1);
        uploader.upload(in);
    }
}
