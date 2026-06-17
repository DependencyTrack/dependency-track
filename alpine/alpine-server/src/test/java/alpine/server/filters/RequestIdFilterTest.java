/*
 * This file is part of Alpine.
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
package alpine.server.filters;

import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class RequestIdFilterTest {

    private RequestIdFilter requestIdFilter;
    private ContainerRequestContext requestContextMock;
    private ContainerResponseContext responseContextMock;

    @BeforeEach
    public void setUp() {
        requestIdFilter = new RequestIdFilter();
        requestContextMock = mock(ContainerRequestContext.class);
        responseContextMock = mock(ContainerResponseContext.class);
    }

    @Test
    public void testProvidedRequestId() throws Exception {
        final Map<String, Boolean> testCases = Map.ofEntries(
                Map.entry("a".repeat(15), false),
                Map.entry("a".repeat(16), true),
                Map.entry("a".repeat(192), true),
                Map.entry("a".repeat(193), false),
                Map.entry("Zm9vYmFyYmF6cXV4cXV1eA==", true),
                Map.entry("112bfb53-eb65-41b5-a093-b73902f43447", true),
                Map.entry("foo%24bar%40baz%C2%A7", false)
        );

        final var softAssertions = new SoftAssertions();
        for (final  Map.Entry<String, Boolean> entry : testCases.entrySet()) {
            final String providedRequestId = entry.getKey();
            final boolean shouldTakeProvidedRequestId = entry.getValue();

            doReturn(providedRequestId).when(requestContextMock).getHeaderString(eq("X-Request-Id"));
            requestIdFilter.filter(requestContextMock);

            final ArgumentCaptor<String> requestIdCaptor = ArgumentCaptor.forClass(String.class);
            verify(requestContextMock).setProperty(eq("requestId"), requestIdCaptor.capture());
            Mockito.reset(requestContextMock);

            if (shouldTakeProvidedRequestId) {
                softAssertions.assertThat(requestIdCaptor.getValue()).isEqualTo(providedRequestId);
            } else {
                softAssertions.assertThat(requestIdCaptor.getValue())
                        .matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
            }
        }

        softAssertions.assertAll();
    }

    @Test
    public void testResponseHeader() throws Exception {
        final var headers = new MultivaluedHashMap<String, Object>();
        doReturn(headers).when(responseContextMock).getHeaders();

        doReturn("foobarbazquxquux").when(requestContextMock).getProperty("requestId");
        requestIdFilter.filter(requestContextMock, responseContextMock);

        assertThat(headers).containsEntry("X-Request-Id", List.of("foobarbazquxquux"));
    }

}