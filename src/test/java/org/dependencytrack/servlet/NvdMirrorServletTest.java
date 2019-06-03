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
package org.dependencytrack.servlet;

import org.dependencytrack.servlets.NvdMirrorServlet;
import org.junit.Before;
import org.junit.Test;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class NvdMirrorServletTest {

    private NvdMirrorServlet servlet;

    @Before
    public void before() throws ServletException {
        final ServletConfig servletConfig = mock(ServletConfig.class);
        final ServletContext servletContext = mock(ServletContext.class);
        when(servletConfig.getServletContext()).thenReturn(servletContext);
        this.servlet = new NvdMirrorServlet();
        servlet.init(servletConfig);
    }

    @Test
    public void doGet() throws Exception {
        final HttpServletRequest request =  mock(HttpServletRequest.class);
        HttpServletResponse response =  mock(HttpServletResponse.class);
        when(request.getMethod()).thenReturn("http");
        servlet.service(request, response);
    }
}
