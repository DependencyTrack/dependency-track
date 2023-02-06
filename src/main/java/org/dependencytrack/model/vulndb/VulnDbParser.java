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
package org.dependencytrack.model.vulndb;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * Model class needed by VulnDBAnalysis task. Class brought over from the vulndb-data-mirror repo:
 * <a href="https://github.com/stevespringett/vulndb-data-mirror">...</a>
 */
public class VulnDbParser {
    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDbParser.class);

    public VulnDbParser() {
    }

    public Status parseStatus(JSONObject root) {
        LOGGER.debug("Parsing JSON node");
        Status status = new Status();
        status.setOrganizationName(root.optString("organization_name"));
        status.setUserNameRequesting(root.optString("user_name_requesting"));
        status.setUserEmailRequesting(root.optString("user_email_address_requesting"));
        status.setSubscriptionEndDate(root.optString("subscription_end_date"));
        status.setApiCallsAllowedPerMonth(root.optString("number_of_api_calls_allowed_per_month"));
        status.setApiCallsMadeThisMonth(root.optString("number_of_api_calls_made_this_month"));
        status.setVulnDbStatistics(root.optString("vulndb_statistics"));
        status.setRawStatus(root.toString());
        return status;
    }

    public <T> Results<T> parse(Object jsonNode, Class<? extends ApiObject> apiObject) {
        LOGGER.debug("Parsing JSON node");
        Results<T> results = new Results();
        JSONObject root;
            root = (JSONObject) jsonNode;

        results.setPage(root.getInt("current_page"));
        results.setTotal(root.getInt("total_entries"));
        results.setRawResults(jsonNode.toString());
        JSONArray rso = root.getJSONArray("results");
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

    public <T> Results<T> parse(String jsonData, Class<? extends ApiObject> apiObject) {
        Object result = null;
        try{
            result = new JSONObject(jsonData);
        }catch (JSONException ex){
            result = new JSONArray(jsonData);
        }
        if(result instanceof JSONObject){
            return this.parse((JSONObject)result, apiObject);
        } else{
            return this.parse((JSONArray) result, apiObject);
        }
    }

    public <T> Results<T> parse(File file, Class<? extends ApiObject> apiObject) throws IOException {
            String jsonData = Files.readString(Paths.get(file.toURI()), Charset.defaultCharset());
            Object result = null;
            try{
                result = new JSONObject(jsonData);
            }catch (JSONException ex){
                result = new JSONArray(jsonData);
            }
            if(result instanceof JSONObject){
                return this.parse((JSONObject)result, apiObject);
            } else{
                return this.parse((JSONArray) result, apiObject);
            }
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

