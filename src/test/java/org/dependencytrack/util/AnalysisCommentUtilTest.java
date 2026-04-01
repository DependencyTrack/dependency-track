package org.dependencytrack.util;

import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.persistence.QueryManager;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class AnalysisCommentUtilTest {

    // ── Generic makeCommentIfChanged ──

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

    @Test
    void makeCommentIfChangedClearedFromActualValue() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        assertTrue(AnalysisCommentUtil.makeCommentIfChanged("prefix", qm, analysis, "HIGH", null, "testuser"));
        verify(qm).makeAnalysisComment(analysis, "prefix: HIGH → (cleared)", "testuser");
    }

    @Test
    void makeCommentIfChangedClearedFromNotSet() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        assertFalse(AnalysisCommentUtil.makeCommentIfChanged("prefix", qm, analysis, "NOT_SET", null, "testuser"));
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }

    // ── makeStateComment ──

    @Test
    void makeStateCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getAnalysisState()).thenReturn(AnalysisState.NOT_SET);
        assertTrue(AnalysisCommentUtil.makeStateComment(qm, analysis, AnalysisState.EXPLOITABLE, "testuser"));
        verify(qm).makeAnalysisComment(analysis, "Analysis: NOT_SET → EXPLOITABLE", "testuser");
    }

    @Test
    void makeStateCommentUnchanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getAnalysisState()).thenReturn(AnalysisState.EXPLOITABLE);
        assertFalse(AnalysisCommentUtil.makeStateComment(qm, analysis, AnalysisState.EXPLOITABLE, "testuser"));
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }

    @Test
    void makeStateCommentNullCurrentDefaultsToNotSet() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getAnalysisState()).thenReturn(null);
        assertTrue(AnalysisCommentUtil.makeStateComment(qm, analysis, AnalysisState.IN_TRIAGE, "testuser"));
        verify(qm).makeAnalysisComment(analysis, "Analysis: NOT_SET → IN_TRIAGE", "testuser");
    }

    // ── makeJustificationComment ──

    @Test
    void makeJustificationCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getAnalysisJustification()).thenReturn(AnalysisJustification.NOT_SET);
        AnalysisCommentUtil.makeJustificationComment(qm, analysis, AnalysisJustification.CODE_NOT_REACHABLE, "testuser");
        verify(qm).makeAnalysisComment(analysis, "Justification: NOT_SET → CODE_NOT_REACHABLE", "testuser");
    }

    // ── makeAnalysisResponseComment ──

    @Test
    void makeAnalysisResponseCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getAnalysisResponse()).thenReturn(AnalysisResponse.NOT_SET);
        AnalysisCommentUtil.makeAnalysisResponseComment(qm, analysis, AnalysisResponse.WORKAROUND_AVAILABLE, "testuser");
        verify(qm).makeAnalysisComment(analysis, "Vendor Response: NOT_SET → WORKAROUND_AVAILABLE", "testuser");
    }

    // ── makeRiskImpactComment ──

    @Test
    void makeRiskImpactCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskImpact()).thenReturn(null);
        AnalysisCommentUtil.makeRiskImpactComment(qm, analysis, "HIGH", "testuser");
        verify(qm).makeAnalysisComment(analysis, "Risk impact: NOT_SET → HIGH", "testuser");
    }

    @Test
    void makeRiskImpactCommentUnchanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskImpact()).thenReturn("HIGH");
        AnalysisCommentUtil.makeRiskImpactComment(qm, analysis, "HIGH", "testuser");
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }

    @Test
    void makeRiskImpactCommentCleared() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskImpact()).thenReturn("HIGH");
        AnalysisCommentUtil.makeRiskImpactComment(qm, analysis, null, "testuser");
        verify(qm).makeAnalysisComment(analysis, "Risk impact: HIGH → (cleared)", "testuser");
    }

    @Test
    void makeRiskImpactCommentClearedFromNotSet() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskImpact()).thenReturn(null);
        AnalysisCommentUtil.makeRiskImpactComment(qm, analysis, null, "testuser");
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }

    @Test
    void makeRiskImpactCommentWithCustomLabel() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskImpact()).thenReturn(null);
        AnalysisCommentUtil.makeRiskImpactComment(qm, analysis, "CRITICAL", "testuser", "Severity Level");
        verify(qm).makeAnalysisComment(analysis, "Severity Level: NOT_SET → CRITICAL", "testuser");
    }

    // ── makeRiskLikelihoodComment ──

    @Test
    void makeRiskLikelihoodCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskLikelihood()).thenReturn(null);
        AnalysisCommentUtil.makeRiskLikelihoodComment(qm, analysis, "LIKELY", "testuser");
        verify(qm).makeAnalysisComment(analysis, "Risk likelihood: NOT_SET → LIKELY", "testuser");
    }

    @Test
    void makeRiskLikelihoodCommentCleared() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskLikelihood()).thenReturn("LIKELY");
        AnalysisCommentUtil.makeRiskLikelihoodComment(qm, analysis, null, "testuser");
        verify(qm).makeAnalysisComment(analysis, "Risk likelihood: LIKELY → (cleared)", "testuser");
    }

    @Test
    void makeRiskLikelihoodCommentWithCustomLabel() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskLikelihood()).thenReturn("LOW");
        AnalysisCommentUtil.makeRiskLikelihoodComment(qm, analysis, "HIGH", "testuser", "Probability");
        verify(qm).makeAnalysisComment(analysis, "Probability: LOW → HIGH", "testuser");
    }

    // ── makeResidualRiskImpactComment ──

    @Test
    void makeResidualRiskImpactCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getResidualRiskImpact()).thenReturn(null);
        AnalysisCommentUtil.makeResidualRiskImpactComment(qm, analysis, "MEDIUM", "testuser");
        verify(qm).makeAnalysisComment(analysis, "Residual risk impact: NOT_SET → MEDIUM", "testuser");
    }

    @Test
    void makeResidualRiskImpactCommentCleared() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getResidualRiskImpact()).thenReturn("MEDIUM");
        AnalysisCommentUtil.makeResidualRiskImpactComment(qm, analysis, null, "testuser");
        verify(qm).makeAnalysisComment(analysis, "Residual risk impact: MEDIUM → (cleared)", "testuser");
    }

    @Test
    void makeResidualRiskImpactCommentWithCustomLabel() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getResidualRiskImpact()).thenReturn("LOW");
        AnalysisCommentUtil.makeResidualRiskImpactComment(qm, analysis, "HIGH", "testuser", "Residual Severity");
        verify(qm).makeAnalysisComment(analysis, "Residual Severity: LOW → HIGH", "testuser");
    }

    // ── makeResidualRiskLikelihoodComment ──

    @Test
    void makeResidualRiskLikelihoodCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getResidualRiskLikelihood()).thenReturn(null);
        AnalysisCommentUtil.makeResidualRiskLikelihoodComment(qm, analysis, "UNLIKELY", "testuser");
        verify(qm).makeAnalysisComment(analysis, "Residual risk likelihood: NOT_SET → UNLIKELY", "testuser");
    }

    @Test
    void makeResidualRiskLikelihoodCommentCleared() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getResidualRiskLikelihood()).thenReturn("UNLIKELY");
        AnalysisCommentUtil.makeResidualRiskLikelihoodComment(qm, analysis, null, "testuser");
        verify(qm).makeAnalysisComment(analysis, "Residual risk likelihood: UNLIKELY → (cleared)", "testuser");
    }

    @Test
    void makeResidualRiskLikelihoodCommentWithCustomLabel() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getResidualRiskLikelihood()).thenReturn("LOW");
        AnalysisCommentUtil.makeResidualRiskLikelihoodComment(qm, analysis, "HIGH", "testuser", "Residual Probability");
        verify(qm).makeAnalysisComment(analysis, "Residual Probability: LOW → HIGH", "testuser");
    }

    // ── makeRiskJustificationComment ──

    @Test
    void makeRiskJustificationCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskJustification()).thenReturn(null);
        AnalysisCommentUtil.makeRiskJustificationComment(qm, analysis, "Component is internal only", "testuser");
        verify(qm).makeAnalysisComment(analysis, "Risk justification: NOT_SET → Component is internal only", "testuser");
    }

    @Test
    void makeRiskJustificationCommentCleared() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getRiskJustification()).thenReturn("Old justification");
        AnalysisCommentUtil.makeRiskJustificationComment(qm, analysis, null, "testuser");
        verify(qm).makeAnalysisComment(analysis, "Risk justification: Old justification → (cleared)", "testuser");
    }

    // ── makeResidualRiskJustificationComment ──

    @Test
    void makeResidualRiskJustificationCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getResidualRiskJustification()).thenReturn(null);
        AnalysisCommentUtil.makeResidualRiskJustificationComment(qm, analysis, "Mitigated via WAF", "testuser");
        verify(qm).makeAnalysisComment(analysis, "Residual risk justification: NOT_SET → Mitigated via WAF", "testuser");
    }

    @Test
    void makeResidualRiskJustificationCommentCleared() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getResidualRiskJustification()).thenReturn("WAF rule applied");
        AnalysisCommentUtil.makeResidualRiskJustificationComment(qm, analysis, null, "testuser");
        verify(qm).makeAnalysisComment(analysis, "Residual risk justification: WAF rule applied → (cleared)", "testuser");
    }

    // ── makeAnalysisDetailsComment ──

    @Test
    void makeAnalysisDetailsCommentChanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getAnalysisDetails()).thenReturn(null);
        AnalysisCommentUtil.makeAnalysisDetailsComment(qm, analysis, "New details text", "testuser");
        verify(qm).makeAnalysisComment(analysis, "Details: New details text", "testuser");
    }

    @Test
    void makeAnalysisDetailsCommentCleared() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getAnalysisDetails()).thenReturn("Old details");
        AnalysisCommentUtil.makeAnalysisDetailsComment(qm, analysis, null, "testuser");
        verify(qm).makeAnalysisComment(analysis, "Details: (cleared)", "testuser");
    }

    @Test
    void makeAnalysisDetailsCommentClearedFromEmpty() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getAnalysisDetails()).thenReturn("");
        AnalysisCommentUtil.makeAnalysisDetailsComment(qm, analysis, null, "testuser");
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }

    @Test
    void makeAnalysisDetailsCommentUnchanged() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.getAnalysisDetails()).thenReturn("Same details");
        AnalysisCommentUtil.makeAnalysisDetailsComment(qm, analysis, "Same details", "testuser");
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }

    // ── makeAnalysisSuppressionComment ──

    @Test
    void makeSuppressionCommentSuppressed() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.isSuppressed()).thenReturn(false);
        assertTrue(AnalysisCommentUtil.makeAnalysisSuppressionComment(qm, analysis, true, "testuser"));
        verify(qm).makeAnalysisComment(analysis, "Suppressed", "testuser");
    }

    @Test
    void makeSuppressionCommentUnsuppressed() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.isSuppressed()).thenReturn(true);
        assertTrue(AnalysisCommentUtil.makeAnalysisSuppressionComment(qm, analysis, false, "testuser"));
        verify(qm).makeAnalysisComment(analysis, "Unsuppressed", "testuser");
    }

    @Test
    void makeSuppressionCommentNoChange() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        when(analysis.isSuppressed()).thenReturn(true);
        assertFalse(AnalysisCommentUtil.makeAnalysisSuppressionComment(qm, analysis, true, "testuser"));
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }

    @Test
    void makeSuppressionCommentNullSuppressed() {
        final var qm = mock(QueryManager.class);
        final var analysis = mock(Analysis.class);
        assertFalse(AnalysisCommentUtil.makeAnalysisSuppressionComment(qm, analysis, null, "testuser"));
        verify(qm, never()).makeAnalysisComment(any(), any(), any());
    }
}