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
package org.dependencytrack.notification.publisher;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

public class ConsolePublisherTest extends PersistenceCapableTest {

    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;

    @Before
    public void setUpStreams() {
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
    }

    @After
    public void restoreStreams() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    @Test
    public void testOutputStream() {
        Notification notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);
        notification.setTitle("Test Notification");
        notification.setContent("This is only a test");
        ConsolePublisher publisher = new ConsolePublisher();
        publisher.inform(notification, null);
        Assert.assertTrue(outContent.toString().contains(expectedResult(notification)));
    }

    @Test
    public void testErrorStream() {
        Notification notification = new Notification();
        notification.setScope(NotificationScope.SYSTEM.name());
        notification.setGroup(NotificationGroup.FILE_SYSTEM.name());
        notification.setLevel(NotificationLevel.ERROR);
        notification.setTitle("Test Notification");
        notification.setContent("This is only a test");
        ConsolePublisher publisher = new ConsolePublisher();
        publisher.inform(notification, null);
        Assert.assertTrue(errContent.toString().contains(expectedResult(notification)));
    }

    private String expectedResult(Notification notification) {
        return "--------------------------------------------------------------------------------" + System.lineSeparator() +
                "Notification" + System.lineSeparator() +
                "  -- timestamp: " + notification.getTimestamp() + System.lineSeparator() +
                "  -- level:     " + notification.getLevel() + System.lineSeparator() +
                "  -- scope:     " + notification.getScope() + System.lineSeparator() +
                "  -- group:     " + notification.getGroup() + System.lineSeparator() +
                "  -- title:     " + notification.getTitle() + System.lineSeparator() +
                "  -- content:   " + notification.getContent() + System.lineSeparator() + System.lineSeparator();
    }
}
