package org.dependencytrack.util;

import java.math.BigDecimal;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.collections4.map.LinkedMap;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilityDetails;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilityDetailsInfo;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilityOverview;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilitySummary;
import org.dependencytrack.model.scheduled.vulnerabilities.VulnerabilitySummaryInfo;
import org.dependencytrack.notification.vo.ScheduledNewVulnerabilitiesIdentified;
import org.junit.Test;
import org.junit.Assert;

import jakarta.json.JsonObject;

public class NotificationUtilTest {
    
    @Test
    public void toJsonWithScheduledNewVulnerabilitiesIdentified() {
        final var project = createProject();
        final var component = createComponent(project);
        final var vuln = createVulnerability();
        final Map<Severity, Integer> mapVulnBySev = new EnumMap<>(Severity.class);
        final Map<Project, VulnerabilitySummaryInfo> mapVulnSummInfos = new LinkedHashMap<>();
        final Map<Project, List<VulnerabilityDetailsInfo>> mapVulnDetailInfos = new LinkedHashMap<>();

        mapVulnBySev.put(Severity.CRITICAL, 1);
        mapVulnSummInfos.put(project, new VulnerabilitySummaryInfo(mapVulnBySev, mapVulnBySev, new LinkedMap<>()));
        mapVulnDetailInfos.put(project, List.of(new VulnerabilityDetailsInfo(
                component.getUuid().toString(),
                component.getName(),
                component.getVersion(),
                component.getGroup(),
                vuln.getSource(),
                vuln.getVulnId(),
                vuln.getSeverity().name(),
                "analyzer",
                "http://example.com",
                "Thu Jan 01 18:31:06 GMT 1970", // Thu Jan 01 18:31:06 GMT 1970
                AnalysisState.EXPLOITABLE.name(),
                false)));

        final ScheduledNewVulnerabilitiesIdentified vo = new ScheduledNewVulnerabilitiesIdentified(
            new VulnerabilityOverview(1, 1, mapVulnBySev, 1, 0),
            new VulnerabilitySummary(mapVulnSummInfos),
            new VulnerabilityDetails(mapVulnDetailInfos)
        );
        JsonObject json = NotificationUtil.toJson(vo);
        System.out.println(json.toString());
        
        Assert.assertEquals(1, json.getJsonObject("overview").getInt("affectedProjectsCount"));
        Assert.assertEquals(1, json.getJsonObject("overview").getInt("newVulnerabilitiesCount"));
        Assert.assertEquals(1, json.getJsonObject("overview").getInt("affectedComponentsCount"));
        Assert.assertEquals(0, json.getJsonObject("overview").getInt("suppressedNewVulnerabilitiesCount"));
        Assert.assertEquals(1, json.getJsonObject("overview").getJsonObject("newVulnerabilitiesBySeverity").getInt("CRITICAL"));
        Assert.assertEquals(0, json.getJsonObject("overview").getInt("suppressedNewVulnerabilitiesCount"));

        Assert.assertEquals(project.getUuid().toString(), json.getJsonObject("summary").getJsonArray("projectSummaries").getJsonObject(0).getJsonObject("project").getString("uuid"));
        Assert.assertEquals(project.getName(), json.getJsonObject("summary").getJsonArray("projectSummaries").getJsonObject(0).getJsonObject("project").getString("name"));
        Assert.assertEquals(project.getVersion(), json.getJsonObject("summary").getJsonArray("projectSummaries").getJsonObject(0).getJsonObject("project").getString("version"));
        Assert.assertEquals(project.getDescription(), json.getJsonObject("summary").getJsonArray("projectSummaries").getJsonObject(0).getJsonObject("project").getString("description"));
        Assert.assertEquals(project.getPurl().toString(), json.getJsonObject("summary").getJsonArray("projectSummaries").getJsonObject(0).getJsonObject("project").getString("purl"));
        Assert.assertEquals("tag1,tag2", json.getJsonObject("summary").getJsonArray("projectSummaries").getJsonObject(0).getJsonObject("project").getString("tags"));
        Assert.assertEquals(1, json.getJsonObject("summary").getJsonArray("projectSummaries").getJsonObject(0).getJsonObject("summary").getJsonObject("newVulnerabilitiesBySeverity").getInt("CRITICAL"));
        Assert.assertEquals(1, json.getJsonObject("summary").getJsonArray("projectSummaries").getJsonObject(0).getJsonObject("summary").getJsonObject("totalProjectVulnerabilitiesBySeverity").getInt("CRITICAL"));
        Assert.assertTrue(json.getJsonObject("summary").getJsonArray("projectSummaries").getJsonObject(0).getJsonObject("summary").getJsonObject("suppressedNewVulnerabilitiesBySeverity").isEmpty());

        Assert.assertEquals(project.getUuid().toString(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonObject("project").getString("uuid"));
        Assert.assertEquals(project.getName(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonObject("project").getString("name"));
        Assert.assertEquals(project.getVersion(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonObject("project").getString("version"));
        Assert.assertEquals(project.getDescription(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonObject("project").getString("description"));
        Assert.assertEquals(project.getPurl().toString(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonObject("project").getString("purl"));
        Assert.assertEquals("tag1,tag2", json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonObject("project").getString("tags"));
        Assert.assertEquals(component.getUuid().toString(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("componentUuid"));
        Assert.assertEquals(component.getName(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("componentName"));
        Assert.assertEquals(component.getVersion(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("componentVersion"));
        Assert.assertEquals(vuln.getSource(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("vulnerabilitySource"));
        Assert.assertEquals(vuln.getVulnId(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("vulnerabilityId"));
        Assert.assertEquals(vuln.getSeverity().toString(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("vulnerabilitySeverity"));
        Assert.assertEquals("analyzer", json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("analyzer"));
        Assert.assertEquals("http://example.com", json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("attributionReferenceUrl"));
        Assert.assertEquals("Thu Jan 01 18:31:06 GMT 1970", json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("attributedOn"));
        Assert.assertEquals(AnalysisState.EXPLOITABLE.name(), json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getString("analysisState"));
        Assert.assertFalse(json.getJsonObject("details").getJsonArray("projectDetails").getJsonObject(0).getJsonArray("findings").getJsonObject(0).getBoolean("suppressed"));

    }

    private static Component createComponent(final Project project) {
        final var component = new Component();
        component.setProject(project);
        component.setUuid(UUID.fromString("94f87321-a5d1-4c2f-b2fe-95165debebc6"));
        component.setName("componentName");
        component.setVersion("componentVersion");
        return component;
    }

    private static Project createProject() {
        final var projectTag1 = new Tag();
        projectTag1.setName("tag1");
        final var projectTag2 = new Tag();
        projectTag2.setName("tag2");

        final var project = new Project();
        project.setUuid(UUID.fromString("c9c9539a-e381-4b36-ac52-6a7ab83b2c95"));
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("pkg:maven/org.acme/projectName@projectVersion");
        project.setTags(List.of(projectTag1, projectTag2));
        return project;
    }

    private static Vulnerability createVulnerability() {
        final var alias = new org.dependencytrack.model.VulnerabilityAlias();
        alias.setInternalId("INT-001");
        alias.setOsvId("OSV-001");

        final var vuln = new org.dependencytrack.model.Vulnerability();
        vuln.setUuid(UUID.fromString("bccec5d5-ec21-4958-b3e8-22a7a866a05a"));
        vuln.setVulnId("INT-001");
        vuln.setSource(org.dependencytrack.model.Vulnerability.Source.INTERNAL);
        vuln.setAliases(List.of(alias));
        vuln.setTitle("vulnerabilityTitle");
        vuln.setSubTitle("vulnerabilitySubTitle");
        vuln.setDescription("vulnerabilityDescription");
        vuln.setRecommendation("vulnerabilityRecommendation");
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(5.5));
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(6.6));
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(1.1));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(2.2));
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vuln.setSeverity(Severity.MEDIUM);
        vuln.setCwes(List.of(666, 777));
        return vuln;
    }
}

