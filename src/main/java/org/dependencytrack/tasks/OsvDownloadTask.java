package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import kong.unirest.json.JSONObject;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.Ecosystem;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import org.dependencytrack.persistence.QueryManager;

import us.springett.cvss.Cvss;
import us.springett.cvss.Score;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
import static org.dependencytrack.model.Severity.getSeverityByLevel;
import static org.dependencytrack.util.VulnerabilityUtil.*;

public class OsvDownloadTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(OsvDownloadTask.class);
    private final boolean isEnabled;
    private HttpUriRequest request;

    public OsvDownloadTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName());
            this.isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
        }
    }

    @Override
    public void inform(Event e) {

        if (e instanceof OsvMirrorEvent && this.isEnabled) {

            for (Ecosystem ecosystem : Ecosystem.values()) {
                LOGGER.info("Updating datasource with Google OSV advisories for ecosystem " + ecosystem.getValue());
                String url = "https://osv-vulnerabilities.storage.googleapis.com/" + ecosystem.getValue() + "/all.zip";
                request = new HttpGet(url);
                try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                    final StatusLine status = response.getStatusLine();
                    if (status.getStatusCode() == 200) {
                        try (InputStream in = response.getEntity().getContent();
                            ZipInputStream zipInput = new ZipInputStream(in)) {
                            unzipFolder(zipInput);
                        }
                    } else {
                        LOGGER.error("Download failed : " + status.getStatusCode() + ": " + status.getReasonPhrase());
                    }
                } catch (Exception ex) {
                    LOGGER.error("Exception while executing Http client request", ex);
                }
            }
        }
    }

    private void unzipFolder(ZipInputStream zipIn) throws IOException {

        BufferedReader reader = new BufferedReader(new InputStreamReader(zipIn));
        OsvAdvisoryParser parser = new OsvAdvisoryParser();
        ZipEntry zipEntry = zipIn.getNextEntry();
        while (zipEntry != null) {

            String line = null;
            StringBuilder out = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                out.append(line);
            }
            JSONObject json = new JSONObject(out.toString());
            final OsvAdvisory osvAdvisory = parser.parse(json);
            if (osvAdvisory != null) {
                updateDatasource(osvAdvisory);
            }
            zipEntry = zipIn.getNextEntry();
            reader = new BufferedReader(new InputStreamReader(zipIn));
        }
        reader.close();
    }

    public void updateDatasource(final OsvAdvisory advisory) {

        try (QueryManager qm = new QueryManager()) {

            LOGGER.debug("Synchronizing Google OSV advisory: " + advisory.getId());
            final List<VulnerableSoftware> vsList = new ArrayList<>();
            Vulnerability synchronizedVulnerability;
            Vulnerability vulnerability = mapAdvisoryToVulnerability(qm, advisory);
            Vulnerability existingVuln = findExistingClashingVulnerability(qm, vulnerability, advisory);

            if (existingVuln != null) {
                synchronizedVulnerability = existingVuln;
                vsList.addAll(existingVuln.getVulnerableSoftware());
            } else {
                synchronizedVulnerability = qm.synchronizeVulnerability(vulnerability, false);
            }

            for (OsvAffectedPackage osvAffectedPackage : advisory.getAffectedPackages()) {
                VulnerableSoftware vs = mapAffectedPackageToVulnerableSoftware(qm, osvAffectedPackage);
                if (vs != null) {
                    // check if it already exists or not
                    VulnerableSoftware existingVulnSoftware = qm.getVulnerableSoftwareByPurl(vs.getPurlType(), vs.getPurlNamespace(), vs.getPurlName(), vs.getVersionEndExcluding(), vs.getVersionEndIncluding(), vs.getVersionStartExcluding(), vs.getVersionStartIncluding());
                    if(existingVulnSoftware == null) {
                        vsList.add(vs);
                    }
                }
            }
            synchronizedVulnerability.setVulnerableSoftware(new ArrayList<> (vsList));
            qm.persist(synchronizedVulnerability);
            LOGGER.debug("Updating vulnerable software for OSV advisory: " + advisory.getId());
            qm.persist(vsList);
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    public Vulnerability mapAdvisoryToVulnerability(final QueryManager qm, final OsvAdvisory advisory) {

        final Vulnerability vuln = new Vulnerability();
        if(advisory.getId() != null) {
            vuln.setSource(extractSource(advisory.getId()));
        }
        vuln.setVulnId(String.valueOf(advisory.getId()));
        vuln.setTitle(advisory.getSummary());
        vuln.setDescription(advisory.getDetails());
        vuln.setPublished(Date.from(advisory.getPublished().toInstant()));
        vuln.setUpdated(Date.from(advisory.getModified().toInstant()));

        if (advisory.getCredits() != null) {
            vuln.setCredits(String.join(", ", advisory.getCredits()));
        }

        if (advisory.getReferences() != null && advisory.getReferences().size() > 0) {
            final StringBuilder sb = new StringBuilder();
            for (String ref : advisory.getReferences()) {
                sb.append("* [").append(ref).append("](").append(ref).append(")\n");
            }
            vuln.setReferences(sb.toString());
        }

        if (advisory.getCweIds() != null) {
            for (int i=0; i<advisory.getCweIds().size(); i++) {
                final Cwe cwe = CweResolver.getInstance().resolve(qm, advisory.getCweIds().get(i));
                if (cwe != null) {
                    vuln.addCwe(cwe);
                }
            }
        }
        vuln.setSeverity(calculateOSVSeverity(advisory));
        vuln.setCvssV2Vector(advisory.getCvssV2Vector());
        vuln.setCvssV3Vector(advisory.getCvssV3Vector());
        return vuln;
    }

    // calculate severity of vulnerability on priority-basis (database, ecosystem)
    public Severity calculateOSVSeverity(OsvAdvisory advisory) {

        // derive from database_specific cvss v3 vector if available
        if(advisory.getCvssV3Vector() != null) {
            Cvss cvss = Cvss.fromVector(advisory.getCvssV3Vector());
            Score score = cvss.calculateScore();
            return normalizedCvssV3Score(score.getBaseScore());
        }
        // derive from database_specific cvss v2 vector if available
        if (advisory.getCvssV2Vector() != null) {
            Cvss cvss = Cvss.fromVector(advisory.getCvssV2Vector());
            Score score = cvss.calculateScore();
            return normalizedCvssV2Score(score.getBaseScore());
        }
        // get database_specific severity string if available
        if (advisory.getSeverity() != null) {
            if (advisory.getSeverity().equalsIgnoreCase("CRITICAL")) {
                return Severity.CRITICAL;
            } else if (advisory.getSeverity().equalsIgnoreCase("HIGH")) {
                return Severity.HIGH;
            } else if (advisory.getSeverity().equalsIgnoreCase("MODERATE")) {
                return Severity.MEDIUM;
            } else if (advisory.getSeverity().equalsIgnoreCase("LOW")) {
                return Severity.LOW;
            }
        }
        // get largest ecosystem_specific severity from its affected packages
        if (advisory.getAffectedPackages() != null) {
            List<Integer> severityLevels = new ArrayList<>();
            for (OsvAffectedPackage vuln : advisory.getAffectedPackages()) {
                severityLevels.add(vuln.getSeverity().getLevel());
            }
            Collections.sort(severityLevels);
            Collections.reverse(severityLevels);
            return getSeverityByLevel(severityLevels.get(0));
        }
        return Severity.UNASSIGNED;
    }

    public Vulnerability.Source extractSource(String vulnId) {

        final String sourceId = vulnId.split("-")[0];
        switch (sourceId) {
            case "GHSA": return Vulnerability.Source.GITHUB;
            case "CVE": return Vulnerability.Source.NVD;
            default: return Vulnerability.Source.OSV;
        }
    }

    public VulnerableSoftware mapAffectedPackageToVulnerableSoftware(final QueryManager qm, final OsvAffectedPackage affectedPackage) {
        if (affectedPackage.getPurl() == null) {
            LOGGER.debug("No PURL provided for affected package " + affectedPackage.getPackageName() + " - skipping");
            return null;
        }

        final PackageURL purl;
        try {
            purl = new PackageURL(affectedPackage.getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Invalid PURL provided for affected package  " + affectedPackage.getPackageName() + " - skipping", e);
            return null;
        }

        final String versionStartIncluding = affectedPackage.getLowerVersionRange();
        final String versionEndExcluding = affectedPackage.getUpperVersionRangeExcluding();
        final String versionEndIncluding = affectedPackage.getUpperVersionRangeIncluding();

        VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(purl.getType(), purl.getNamespace(), purl.getName(),
                versionEndExcluding, versionEndIncluding, null, versionStartIncluding);
        if (vs != null) {
            return vs;
        }

        vs = new VulnerableSoftware();
        vs.setPurlType(purl.getType());
        vs.setPurlNamespace(purl.getNamespace());
        vs.setPurlName(purl.getName());
        vs.setVulnerable(true);
        vs.setVersion(affectedPackage.getVersion());
        vs.setVersionStartIncluding(versionStartIncluding);
        vs.setVersionEndExcluding(versionEndExcluding);
        vs.setVersionEndIncluding(versionEndIncluding);
        return vs;
    }

    public Vulnerability findExistingClashingVulnerability(QueryManager qm, Vulnerability vulnerability, OsvAdvisory advisory) {

        Vulnerability existing = null;
        if (isVulnerabilitySourceClashingWithGithubOrNvd(vulnerability.getSource())) {
            existing = qm.getVulnerabilityByVulnId(vulnerability.getSource(), vulnerability.getVulnId());
        } else if (advisory.getAliases() != null) {
            for(String alias : advisory.getAliases()) {
                String sourceOfAlias = extractSource(alias).toString();
                if(isVulnerabilitySourceClashingWithGithubOrNvd(sourceOfAlias)) {
                    existing = qm.getVulnerabilityByVulnId(sourceOfAlias, alias);
                    if (existing != null) break;
                }
            }
        }
        return existing;
    }

    private boolean isVulnerabilitySourceClashingWithGithubOrNvd(String source) {

        return Vulnerability.Source.GITHUB.toString().equals(source)
                || Vulnerability.Source.NVD.toString().equals(source);
    }
}