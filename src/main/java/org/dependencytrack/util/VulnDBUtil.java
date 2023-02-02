package org.dependencytrack.util;

import oauth.signpost.OAuthConsumer;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.dependencytrack.tasks.scanners.BaseComponentAnalyzerTask;
import org.json.JSONArray;
import org.json.JSONObject;
import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.exception.OAuthException;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.dependencytrack.model.VulnDb.Cpe;
import org.dependencytrack.model.VulnDb.Product;
import org.dependencytrack.model.VulnDb.Results;
import org.dependencytrack.model.VulnDb.Vendor;
import org.dependencytrack.model.VulnDb.Version;
import org.dependencytrack.model.VulnDb.ApiObject;
import org.dependencytrack.model.VulnDb.Vulnerability;
import org.dependencytrack.model.VulnDb.Classification;
import org.dependencytrack.model.VulnDb.Author;
import org.dependencytrack.model.VulnDb.CvssV2Metric;
import org.dependencytrack.model.VulnDb.CvssV3Metric;
import org.dependencytrack.model.VulnDb.NvdAdditionalInfo;
import org.dependencytrack.model.VulnDb.ExternalText;
import org.dependencytrack.model.VulnDb.ExternalReference;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class VulnDBUtil {

    private final String consumerKey;
    private final String consumerSecret;

    private final String apiBaseUrl;


    public VulnDBUtil(String consumerKey, String consumerSecret, String apiBaseUrl) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
        this.apiBaseUrl = apiBaseUrl;
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDBUtil.class);

    public Results getVulnerabilitiesByCpe(String cpe, int size, int page) {
        String encodedCpe = cpe;

        try {
            encodedCpe = URLEncoder.encode(cpe, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException var6) {
            LOGGER.error("An error occurred while URL encoding a CPE", var6);
        }

        return this.getResults(apiBaseUrl+"/api/v1/vulnerabilities/find_by_cpe?&cpe=" + encodedCpe, Vulnerability.class, size, page);
    }

    private Results getResults(String url, Class clazz, int size, int page) {
        String modifiedUrl = url.contains("?") ? url + "&" : url + "?";
        CloseableHttpResponse response = this.makeRequest(modifiedUrl + "size=" + size + "&page=" + page);
        Results results;
        try{
        if (response != null) {
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                String responseString = EntityUtils.toString(response.getEntity());
                var jsonObject = new JSONObject(responseString);
                results = parse(jsonObject, clazz);
                return results;
            } else {
                results = new Results();
                results.setErrorCondition("An unexpected response was returned from VulnDB. Request unsuccessful: " + response.getStatusLine().getStatusCode() + " - " + response.getStatusLine().getReasonPhrase());
                this.logHttpResponseError(response);
                return results;
            }
        } else {
            results = new Results();
            results.setErrorCondition("No response was returned from VulnDB. No further information is available.");
            return results;
        }
    }catch (IOException ex){
            LOGGER.error("An error occurred making request: " + url);
            return null;
        }
    }

    private CloseableHttpResponse makeRequest(String url) {
        try {
            OAuthConsumer consumer = new DefaultOAuthConsumer(this.consumerKey, this.consumerSecret);
            String signed = consumer.sign(url);
            URIBuilder uriBuilder = new URIBuilder(signed);
            HttpGet request = new HttpGet(uriBuilder.build().toString());
            request.addHeader("X-User-Agent", "VulnDB Data Mirror (https://github.com/stevespringett/vulndb-data-mirror)");
            return HttpClientPool.getClient().execute(request);
        } catch (IOException | OAuthException | URISyntaxException var4) {
            LOGGER.error("An error occurred making request: " + url, var4.getMessage()+ "stack trace: "+ Arrays.toString(var4.getStackTrace()));
            return null;
        }
    }

    private void logHttpResponseError(CloseableHttpResponse response) {
        LOGGER.error("Response was not successful: " + response.getStatusLine().getStatusCode() + " - " + response.getStatusLine().getReasonPhrase());
        System.err.println("\n" + response.getStatusLine().getStatusCode() + " - " + response.getStatusLine().getReasonPhrase());
    }

    public <T> Results<T> parse(JSONObject jsonResponse, Class<? extends ApiObject> apiObject) {
        LOGGER.debug("Parsing JSON response");
        Results<T> results = new Results();
        results.setPage(jsonResponse.getInt("current_page"));
        results.setTotal(jsonResponse.getInt("total_entries"));
        results.setRawResults(jsonResponse.toString());
        JSONArray rso = jsonResponse.getJSONArray("results");
        if (Product.class == apiObject) {
            results.setResults(this.parseProducts(rso));
        } else if (Vendor.class == apiObject) {
            results.setResults(this.parseVendors(rso));
        } else if (Version.class == apiObject) {
            results.setResults(this.parseVersions(rso));
        } else if (Vulnerability.class == apiObject) {
            results.setResults(this.parseVulnerabilities(rso));
        }

        return results;
    }

    private List<Product> parseProducts(JSONArray rso) {
        List<Product> products = null;
        if (rso != null) {
            products = new ArrayList();

            for(int i = 0; i < rso.length(); ++i) {
                JSONObject object = rso.getJSONObject(i);
                Product product = new Product();
                product.setId(object.getInt("id"));
                product.setName(StringUtils.trimToNull(object.optString("name", (String)null)));
                product.setVersions(this.parseVersions(object.optJSONArray("versions")));
                products.add(product);
            }
        }

        return products;
    }

    private List<Vendor> parseVendors(JSONArray rso) {
        List<Vendor> vendors = null;
        if (rso != null) {
            vendors = new ArrayList();

            for(int i = 0; i < rso.length(); ++i) {
                JSONObject object = rso.getJSONObject(i);
                if (object.has("vendor")) {
                    JSONObject childObject = object.getJSONObject("vendor");
                    Vendor vendor = this.parseVendor(childObject);
                    vendors.add(vendor);
                } else {
                    Vendor vendor = this.parseVendor(object);
                    vendors.add(vendor);
                }
            }
        }

        return vendors;
    }

    private Vendor parseVendor(JSONObject object) {
        Vendor vendor = new Vendor();
        vendor.setId(object.getInt("id"));
        vendor.setName(StringUtils.trimToNull(object.optString("name", (String)null)));
        vendor.setShortName(StringUtils.trimToNull(object.optString("short_name", (String)null)));
        vendor.setVendorUrl(StringUtils.trimToNull(object.optString("vendor_url", (String)null)));
        vendor.setProducts(this.parseProducts(object.optJSONArray("products")));
        return vendor;
    }

    private List<Version> parseVersions(JSONArray rso) {
        List<Version> versions = null;
        if (rso != null) {
            versions = new ArrayList();

            for(int i = 0; i < rso.length(); ++i) {
                JSONObject object = rso.getJSONObject(i);
                Version version = new Version();
                version.setId(object.getInt("id"));
                version.setName(StringUtils.trimToNull(object.optString("name", (String)null)));
                version.setAffected(object.optBoolean("affected", false));
                version.setCpes(this.parseCpes(object.optJSONArray("cpe")));
                versions.add(version);
            }
        }

        return versions;
    }

    private List<Cpe> parseCpes(JSONArray rso) {
        List<Cpe> cpes = null;
        if (rso != null) {
            cpes = new ArrayList();

            for(int i = 0; i < rso.length(); ++i) {
                JSONObject object = rso.getJSONObject(i);
                Cpe cpe = new Cpe();
                cpe.setCpe(StringUtils.trimToNull(object.optString("cpe", (String)null)));
                cpe.setType(StringUtils.trimToNull(object.optString("type", (String)null)));
                cpes.add(cpe);
            }
        }

        return cpes;
    }

    private List<Vulnerability> parseVulnerabilities(JSONArray rso) {
        List<Vulnerability> vulnerabilities = null;
        if (rso != null) {
            vulnerabilities = new ArrayList();

            for(int i = 0; i < rso.length(); ++i) {
                JSONObject object = rso.getJSONObject(i);
                Vulnerability vulnerability = new Vulnerability();
                vulnerability.setId(object.getInt("vulndb_id"));
                vulnerability.setTitle(StringUtils.trimToNull(object.optString("title", (String)null)));
                vulnerability.setDisclosureDate(StringUtils.trimToNull(object.optString("disclosure_date", (String)null)));
                vulnerability.setDiscoveryDate(StringUtils.trimToNull(object.optString("discovery_date", (String)null)));
                vulnerability.setExploitPublishDate(StringUtils.trimToNull(object.optString("exploit_publish_date", (String)null)));
                vulnerability.setKeywords(StringUtils.trimToNull(object.optString("keywords", (String)null)));
                vulnerability.setShortDescription(StringUtils.trimToNull(object.optString("short_description", (String)null)));
                vulnerability.setDescription(StringUtils.trimToNull(object.optString("description", (String)null)));
                vulnerability.setSolution(StringUtils.trimToNull(object.optString("solution", (String)null)));
                vulnerability.setManualNotes(StringUtils.trimToNull(object.optString("manual_notes", (String)null)));
                vulnerability.setTechnicalDescription(StringUtils.trimToNull(object.optString("t_description", (String)null)));
                vulnerability.setSolutionDate(StringUtils.trimToNull(object.optString("solution_date", (String)null)));
                vulnerability.setVendorInformedDate(StringUtils.trimToNull(object.optString("vendor_informed_date", (String)null)));
                vulnerability.setVendorAckDate(StringUtils.trimToNull(object.optString("vendor_ack_date", (String)null)));
                vulnerability.setThirdPartySolutionDate(StringUtils.trimToNull(object.optString("third_party_solution_date", (String)null)));
                JSONArray classifications = object.optJSONArray("classifications");
                if (classifications != null) {
                    for(int j = 0; j < classifications.length(); ++j) {
                        JSONObject jso = classifications.getJSONObject(j);
                        Classification classification = new Classification();
                        classification.setId(jso.getInt("id"));
                        classification.setName(StringUtils.trimToNull(jso.optString("name", (String)null)));
                        classification.setLongname(StringUtils.trimToNull(jso.optString("longname", (String)null)));
                        classification.setDescription(StringUtils.trimToNull(jso.optString("description", (String)null)));
                        classification.setMediumtext(StringUtils.trimToNull(jso.optString("mediumtext", (String)null)));
                        vulnerability.addClassifications(classification);
                    }
                }

                JSONArray authors = object.optJSONArray("authors");
                if (authors != null) {
                    for(int j = 0; j < authors.length(); ++j) {
                        JSONObject jso = authors.getJSONObject(j);
                        Author author = new Author();
                        author.setId(jso.getInt("id"));
                        author.setName(StringUtils.trimToNull(jso.optString("name", (String)null)));
                        author.setCompany(StringUtils.trimToNull(jso.optString("company", (String)null)));
                        author.setEmail(StringUtils.trimToNull(jso.optString("email", (String)null)));
                        author.setCompanyUrl(StringUtils.trimToNull(jso.optString("company_url", (String)null)));
                        author.setCountry(StringUtils.trimToNull(jso.optString("country", (String)null)));
                        vulnerability.addAuthor(author);
                    }
                }

                JSONArray extRefs = object.optJSONArray("ext_references");
                if (extRefs != null) {
                    for(int j = 0; j < extRefs.length(); ++j) {
                        JSONObject jso = extRefs.getJSONObject(j);
                        ExternalReference externalReference = new ExternalReference();
                        externalReference.setType(StringUtils.trimToNull(jso.optString("type", (String)null)));
                        externalReference.setValue(StringUtils.trimToNull(jso.optString("value", (String)null)));
                        vulnerability.addExtReference(externalReference);
                    }
                }

                JSONArray extTexts = object.optJSONArray("ext_texts");
                if (extTexts != null) {
                    for(int j = 0; j < extTexts.length(); ++j) {
                        JSONObject jso = extTexts.getJSONObject(j);
                        ExternalText externalText = new ExternalText();
                        externalText.setType(StringUtils.trimToNull(jso.optString("type", (String)null)));
                        externalText.setValue(StringUtils.trimToNull(jso.optString("value", (String)null)));
                        vulnerability.addExtText(externalText);
                    }
                }

                JSONArray cvssv2Metrics = object.optJSONArray("cvss_metrics");
                if (cvssv2Metrics != null) {
                    for(int j = 0; j < cvssv2Metrics.length(); ++j) {
                        JSONObject jso = cvssv2Metrics.getJSONObject(j);
                        CvssV2Metric metric = new CvssV2Metric();
                        metric.setId(jso.getInt("id"));
                        metric.setAccessComplexity(StringUtils.trimToNull(jso.optString("access_complexity", (String)null)));
                        metric.setCveId(StringUtils.trimToNull(jso.optString("cve_id", (String)null)));
                        metric.setSource(StringUtils.trimToNull(jso.optString("source", (String)null)));
                        metric.setAvailabilityImpact(StringUtils.trimToNull(jso.optString("availability_impact", (String)null)));
                        metric.setConfidentialityImpact(StringUtils.trimToNull(jso.optString("confidentiality_impact", (String)null)));
                        metric.setAuthentication(StringUtils.trimToNull(jso.optString("authentication", (String)null)));
                        metric.setCalculatedCvssBaseScore(jso.optBigDecimal("calculated_cvss_base_score", (BigDecimal)null));
                        metric.setGeneratedOn(StringUtils.trimToNull(jso.optString("generated_on", (String)null)));
                        metric.setScore(jso.optBigDecimal("score", (BigDecimal)null));
                        metric.setAccessVector(StringUtils.trimToNull(jso.optString("access_vector", (String)null)));
                        metric.setIntegrityImpact(StringUtils.trimToNull(jso.optString("integrity_impact", (String)null)));
                        vulnerability.addCvssV2Metric(metric);
                    }
                }

                JSONArray cvssv3Metrics = object.optJSONArray("cvss_version_three_metrics");
                if (cvssv3Metrics != null) {
                    for(int j = 0; j < cvssv3Metrics.length(); ++j) {
                        JSONObject jso = cvssv3Metrics.getJSONObject(j);
                        CvssV3Metric metric = new CvssV3Metric();
                        metric.setId(jso.getInt("id"));
                        metric.setAttackComplexity(StringUtils.trimToNull(jso.optString("attack_complexity", (String)null)));
                        metric.setScope(StringUtils.trimToNull(jso.optString("scope", (String)null)));
                        metric.setAttackVector(StringUtils.trimToNull(jso.optString("attack_vector", (String)null)));
                        metric.setAvailabilityImpact(StringUtils.trimToNull(jso.optString("availability_impact", (String)null)));
                        metric.setScore(jso.optBigDecimal("score", (BigDecimal)null));
                        metric.setPrivilegesRequired(StringUtils.trimToNull(jso.optString("privileges_required", (String)null)));
                        metric.setUserInteraction(StringUtils.trimToNull(jso.optString("user_interaction", (String)null)));
                        metric.setCveId(StringUtils.trimToNull(jso.optString("cve_id", (String)null)));
                        metric.setSource(StringUtils.trimToNull(jso.optString("source", (String)null)));
                        metric.setConfidentialityImpact(StringUtils.trimToNull(jso.optString("confidentiality_impact", (String)null)));
                        metric.setCalculatedCvssBaseScore(jso.optBigDecimal("calculated_cvss_base_score", (BigDecimal)null));
                        metric.setGeneratedOn(StringUtils.trimToNull(jso.optString("generated_on", (String)null)));
                        metric.setIntegrityImpact(StringUtils.trimToNull(jso.optString("integrity_impact", (String)null)));
                        vulnerability.addCvssV3Metric(metric);
                    }
                }

                JSONArray nvdInfo = object.optJSONArray("nvd_additional_information");
                if (nvdInfo != null) {
                    for(int j = 0; j < nvdInfo.length(); ++j) {
                        JSONObject jso = nvdInfo.getJSONObject(j);
                        NvdAdditionalInfo nvdAdditionalInfo = new NvdAdditionalInfo();
                        nvdAdditionalInfo.setSummary(StringUtils.trimToNull(jso.optString("summary", (String)null)));
                        nvdAdditionalInfo.setCweId(StringUtils.trimToNull(jso.optString("cwe_id", (String)null)));
                        nvdAdditionalInfo.setCveId(StringUtils.trimToNull(jso.optString("cve_id", (String)null)));
                        vulnerability.setNvdAdditionalInfo(nvdAdditionalInfo);
                    }
                }

                JSONArray vendors = object.optJSONArray("vendors");
                vulnerability.setVendors(this.parseVendors(vendors));
                vulnerabilities.add(vulnerability);
            }
        }

        return vulnerabilities;
    }
}
