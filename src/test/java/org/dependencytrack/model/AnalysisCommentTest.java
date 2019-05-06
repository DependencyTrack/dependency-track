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
package org.dependencytrack.model;

import org.junit.Assert;
import org.junit.Test;
import java.util.Date;

public class AnalysisCommentTest {

    @Test
    public void testId() {
        AnalysisComment comment = new AnalysisComment();
        comment.setId(111L);
        Assert.assertEquals(111L, comment.getId());
    }

    @Test
    public void testAnalysis() {
        Analysis analysis = new Analysis();
        AnalysisComment comment = new AnalysisComment();
        comment.setAnalysis(analysis);
        Assert.assertEquals(analysis, comment.getAnalysis());
    }

    @Test
    public void testTimestamp() {
        Date date = new Date();
        AnalysisComment comment = new AnalysisComment();
        comment.setTimestamp(date);
        Assert.assertEquals(date, comment.getTimestamp());
    }

    @Test
    public void testComment() {
        String commentString = "This is a test comment";
        AnalysisComment comment = new AnalysisComment();
        comment.setComment(commentString);
        Assert.assertEquals(commentString, comment.getComment());
    }

    @Test
    public void testCommenter() {
        String commenter = "John Doe";
        AnalysisComment comment = new AnalysisComment();
        comment.setCommenter(commenter);
        Assert.assertEquals(commenter, comment.getCommenter());
    }
} 
