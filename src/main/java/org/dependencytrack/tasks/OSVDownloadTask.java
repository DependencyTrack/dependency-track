package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import kong.unirest.json.JSONObject;
import org.dependencytrack.event.GoogleOSVMirrorEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.osv.GoogleOSVAdvisoryParser;
import org.dependencytrack.parser.osv.model.OSVAdvisory;
import org.dependencytrack.parser.osv.model.OSVVulnerability;
import org.dependencytrack.persistence.QueryManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;

public class OSVDownloadTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(OSVDownloadTask.class);
    private final boolean isEnabled;

    public OSVDownloadTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName());
            this.isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
        }
    }

    @Override
    public void inform(Event e) {

        if (e instanceof GoogleOSVMirrorEvent && this.isEnabled) {

            try {
                // TODO: Below functionality is being run for one ecosystem for example, it will be run for all ecosystems
                URL url = new URL("https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip");
                ZipInputStream zipIn = new ZipInputStream(url.openStream());
                unzipFolder(zipIn);
                zipIn.closeEntry();
            } catch (IOException exception) {
                exception.printStackTrace();
            }
        }
    }

    private void unzipFolder(ZipInputStream zipIn) throws IOException {

        BufferedReader reader;
        GoogleOSVAdvisoryParser parser = new GoogleOSVAdvisoryParser();
        try {
            ZipEntry zipEntry = zipIn.getNextEntry();
            while (zipEntry != null) {

                reader = new BufferedReader(new InputStreamReader(zipIn));
                String line = null;
                StringBuilder out = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    out.append(line);
                }
                JSONObject json = new JSONObject(out.toString());
                System.out.println(json);
                final OSVAdvisory osvAdvisory = parser.parse(json);
                updateDatasource(osvAdvisory);
                zipEntry = zipIn.getNextEntry();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void updateDatasource(final OSVAdvisory advisory) {
        LOGGER.info("Updating datasource with Google OSV advisories");
        try (QueryManager qm = new QueryManager()) {

            LOGGER.debug("Synchronizing Google OSV advisory: " + advisory.getId());
            final Vulnerability synchronizedVulnerability = qm.synchronizeVulnerability(mapAdvisoryToVulnerability(qm, advisory), false);
            final List<VulnerableSoftware> vsList = new ArrayList<>();
            for (OSVVulnerability osvVulnerability: advisory.getVulnerabilities()) {
                VulnerableSoftware vs = mapVulnerabilityToVulnerableSoftware(qm, osvVulnerability);
                if (vs != null) {
                    vsList.add(vs);
                }
            }
            LOGGER.debug("Updating vulnerable software for OSV advisory: " + advisory.getId());
            qm.persist(vsList);
            synchronizedVulnerability.setVulnerableSoftware(vsList);
            qm.persist(synchronizedVulnerability);
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    private Vulnerability mapAdvisoryToVulnerability(final QueryManager qm, final OSVAdvisory advisory) {

        final Vulnerability vuln = new Vulnerability();
        vuln.setSource(Vulnerability.Source.GOOGLE);
        vuln.setVulnId(String.valueOf(advisory.getId()));
        vuln.setTitle(advisory.getSummary());
        vuln.setDescription(advisory.getDetails());
        vuln.setPublished(Date.from(advisory.getPublished().toInstant()));
        vuln.setUpdated(Date.from(advisory.getModified().toInstant()));

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

        if (advisory.getSeverity() != null) {
            if (advisory.getSeverity().equalsIgnoreCase("CRITICAL")) {
                vuln.setSeverity(Severity.CRITICAL);
            } else if (advisory.getSeverity().equalsIgnoreCase("HIGH")) {
                vuln.setSeverity(Severity.HIGH);
            } else if (advisory.getSeverity().equalsIgnoreCase("MODERATE")) {
                vuln.setSeverity(Severity.MEDIUM);
            } else if (advisory.getSeverity().equalsIgnoreCase("LOW")) {
                vuln.setSeverity(Severity.LOW);
            } else {
                vuln.setSeverity(Severity.UNASSIGNED);
            }
        } else {
            vuln.setSeverity(Severity.UNASSIGNED);
        }
        return vuln;
    }

    private VulnerableSoftware mapVulnerabilityToVulnerableSoftware(final QueryManager qm, final OSVVulnerability vuln) {

        List<String> versions = vuln.getVersions();
        String versionStartIncluding = null;
        String versionEndIncluding = null;
        if (versions != null) {
            versionStartIncluding = versions.get(0);
            versionEndIncluding = versions.get(versions.size() - 1);
        }
        final String purl = vuln.getPurl();
        if (purl == null) return null;

        VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(purl);
        if (vs != null) {
            return vs;
        }
        vs = new VulnerableSoftware();
        vs.setVulnerable(true);
        vs.setPurlType(vuln.getPackageEcosystem());
        vs.setPurlNamespace(vuln.getPackageName());
        vs.setPurlName(purl);
        vs.setVersionStartIncluding(versionStartIncluding);
        vs.setVersionEndIncluding(versionEndIncluding);
        return vs;
    }

//      WAY 2 : to use google storage library instead of downloading data from https

//     private void downloadFromStorage() {
//
//         String bucketName = "osv-vulnerabilities";
//
//         Storage storage = StorageOptions.getUnauthenticatedInstance().getService();
//         Page<Blob> blobs = storage.list(bucketName);
//
//            for (Blob blob : blobs.iterateAll()) {
//                System.out.println(blob.getName());
//            }
//         Blob blob = blobs.getValues().iterator().next();
//         System.out.println(blob);
//         if (blob.getMetadata() != null) {
//             System.out.println("\n\n\nUser metadata:");
//             for (Map.Entry<String, String> userMetadata : blob.getMetadata().entrySet()) {
//                 System.out.println(userMetadata.getKey() + "=" + userMetadata.getValue());
//             }
//         }
//     }
}