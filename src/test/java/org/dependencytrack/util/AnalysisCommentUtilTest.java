package org.dependencytrack.util;

import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.persistence.QueryManager;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class AnalysisCommentUtilTest {
    @Test
    void makeCommentIfChangedNull() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        assertFalse(AnalysisCommentUtil.makeCommentIfChanged("prefix", qm, analysis, AnalysisResponse.NOT_SET, null, "testuser"));
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }

    @Test
    void makeCommentIfChangedWithChange() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        assertTrue(AnalysisCommentUtil.makeCommentIfChanged("prefix", qm, analysis, AnalysisResponse.NOT_SET, AnalysisResponse.WILL_NOT_FIX, "testuser"));
        verify(qm).makeAnalysisComment(analysis, "prefix: NOT_SET → WILL_NOT_FIX", "testuser");
    }

    @Test
    void makeCommentIfChangedWithoutChanges() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        assertFalse(AnalysisCommentUtil.makeCommentIfChanged("prefix", qm, analysis, AnalysisResponse.WILL_NOT_FIX, AnalysisResponse.WILL_NOT_FIX, "testuser"));
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }
}