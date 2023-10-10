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
package org.dependencytrack.parser.vulndb;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.parser.vulndb.model.ApiObject;
import org.dependencytrack.parser.vulndb.model.Author;
import org.dependencytrack.parser.vulndb.model.Classification;
import org.dependencytrack.parser.vulndb.model.Cpe;
import org.dependencytrack.parser.vulndb.model.CvssV2Metric;
import org.dependencytrack.parser.vulndb.model.CvssV3Metric;
import org.dependencytrack.parser.vulndb.model.ExternalReference;
import org.dependencytrack.parser.vulndb.model.ExternalText;
import org.dependencytrack.parser.vulndb.model.NvdAdditionalInfo;
import org.dependencytrack.parser.vulndb.model.Product;
import org.dependencytrack.parser.vulndb.model.Results;
import org.dependencytrack.parser.vulndb.model.Status;
import org.dependencytrack.parser.vulndb.model.Vendor;
import org.dependencytrack.parser.vulndb.model.Version;
import org.dependencytrack.parser.vulndb.model.Vulnerability;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

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
        Status status = new Status(root.optString("organization_name"), root.optString("user_name_requesting"),
                root.optString("user_email_address_requesting"),
                root.optString("subscription_end_date"),
                root.optString("number_of_api_calls_allowed_per_month"),
                root.optString("number_of_api_calls_made_this_month"),
                root.optString("vulndb_statistics"),
                root.toString()
        );
        return status;
    }

    public <T> Results<T> parse(Object jsonNode, Class<? extends ApiObject> apiObject) {
        LOGGER.debug("Parsing JSON node");

        final Results<T> results = new Results<>();
        JSONObject root;
        root = (JSONObject) jsonNode;
        results.setPage(root.getInt("current_page"));
        results.setTotal(root.getInt("total_entries"));
        results.setRawResults(jsonNode.toString());
        final JSONArray rso = root.getJSONArray("results");

        if (Product.class == apiObject) {
            results.setResults(parseProducts(rso));
        } else if (Vendor.class == apiObject) {
            results.setResults(parseVendors(rso));
        } else if (Version.class == apiObject) {
            results.setResults(parseVersions(rso));
        } else if (Vulnerability.class == apiObject) {
            results.setResults(parseVulnerabilities(rso));
        }
        return results;
    }

    public <T> Results<T> parse(String jsonData, Class<? extends ApiObject> apiObject) {
        Object result = null;
        try {
            result = new JSONObject(jsonData);
        } catch (JSONException ex) {
            result = new JSONArray(jsonData);
        }
        if (result instanceof JSONObject) {
            return this.parse((JSONObject) result, apiObject);
        } else {
            return this.parse((JSONArray) result, apiObject);
        }
    }

    public <T> Results<T> parse(File file, Class<? extends ApiObject> apiObject) throws IOException {
        String jsonData = Files.readString(Paths.get(file.toURI()), Charset.defaultCharset());
        Object result = null;
        try {
            result = new JSONObject(jsonData);
        } catch (JSONException ex) {
            result = new JSONArray(jsonData);
        }
        if (result instanceof JSONObject) {
            return this.parse((JSONObject) result, apiObject);
        } else {
            return this.parse((JSONArray) result, apiObject);
        }
    }

    private List<Cpe> parseCpes(JSONArray rso) {
        List<Cpe> cpes = null;
        if (rso != null) {
            cpes = new ArrayList();

            for (int i = 0; i < rso.length(); ++i) {
                JSONObject object = rso.getJSONObject(i);
                Cpe cpe = new Cpe(StringUtils.trimToNull(object.optString("cpe", (String) null)), StringUtils.trimToNull(object.optString("type", (String) null)));
                cpes.add(cpe);
            }
        }

        return cpes;
    }

    private List<Product> parseProducts(JSONArray rso) {
        List<Product> products = null;
        if (rso != null) {
            products = new ArrayList();

            for (int i = 0; i < rso.length(); ++i) {
                JSONObject object = rso.getJSONObject(i);
                Product product = new Product(object.getInt("id"),
                        StringUtils.trimToNull(object.optString("name", (String) null)),
                        this.parseVersions(object.optJSONArray("versions")));
                products.add(product);
            }
        }

        return products;
    }

    private List<Vendor> parseVendors(JSONArray rso) {
        List<Vendor> vendors = null;
        if (rso != null) {
            vendors = new ArrayList();

            for (int i = 0; i < rso.length(); ++i) {
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
        Vendor vendor = new Vendor(object.getInt("id"),
                StringUtils.trimToNull(object.optString("name", (String) null)),
                StringUtils.trimToNull(object.optString("short_name", (String) null)),
                StringUtils.trimToNull(object.optString("vendor_url", (String) null)),
                this.parseProducts(object.optJSONArray("products")));
        return vendor;
    }

    private List<Version> parseVersions(JSONArray rso) {
        List<Version> versions = null;
        if (rso != null) {
            versions = new ArrayList();

            for (int i = 0; i < rso.length(); ++i) {
                JSONObject object = rso.getJSONObject(i);
                Version version = new Version(object.getInt("id"),
                        StringUtils.trimToNull(object.optString("name", (String) null)),
                        object.optBoolean("affected", false),
                        this.parseCpes(object.optJSONArray("cpe")));
                versions.add(version);
            }
        }

        return versions;
    }

    private List<Vulnerability> parseVulnerabilities(JSONArray rso) {
        List<Vulnerability> vulnerabilities = null;
        if (rso != null) {
            vulnerabilities = new ArrayList();

            for (int i = 0; i < rso.length(); ++i) {
                JSONObject object = rso.getJSONObject(i);
                JSONArray classifications = object.optJSONArray("classifications");
                List<Classification> classificationList = new ArrayList<>();
                if (classifications != null) {
                    for (int j = 0; j < classifications.length(); ++j) {
                        JSONObject jso = classifications.getJSONObject(j);
                        Classification classification = new Classification(jso.getInt("id"), StringUtils.trimToNull(jso.optString("name", (String) null)), StringUtils.trimToNull(jso.optString("longname", (String) null)), StringUtils.trimToNull(jso.optString("description", (String) null)),
                                StringUtils.trimToNull(jso.optString("mediumtext", (String) null)));
                        classificationList.add(classification);
                    }
                }

                JSONArray authors = object.optJSONArray("authors");
                List<Author> authorList = new ArrayList<>();
                if (authors != null) {
                    for (int j = 0; j < authors.length(); ++j) {
                        JSONObject jso = authors.getJSONObject(j);
                        Author author = new Author(jso.getInt("id"), StringUtils.trimToNull(jso.optString("name", (String) null)), StringUtils.trimToNull(jso.optString("company", (String) null)),
                                StringUtils.trimToNull(jso.optString("email", (String) null)),
                                StringUtils.trimToNull(jso.optString("company_url", (String) null)),
                                StringUtils.trimToNull(jso.optString("country", (String) null)));
                        authorList.add(author);
                    }
                }

                JSONArray extRefs = object.optJSONArray("ext_references");
                List<ExternalReference> externalReferenceList = new ArrayList<>();
                if (extRefs != null) {
                    for (int j = 0; j < extRefs.length(); ++j) {
                        JSONObject jso = extRefs.getJSONObject(j);
                        ExternalReference externalReference = new ExternalReference(StringUtils.trimToNull(jso.optString("type", (String) null)),
                                StringUtils.trimToNull(jso.optString("value", (String) null)));
                        externalReferenceList.add(externalReference);
                    }
                }

                JSONArray extTexts = object.optJSONArray("ext_texts");
                List<ExternalText> externalTextList = new ArrayList<>();
                if (extTexts != null) {
                    for (int j = 0; j < extTexts.length(); ++j) {
                        JSONObject jso = extTexts.getJSONObject(j);
                        ExternalText externalText = new ExternalText(StringUtils.trimToNull(jso.optString("type", (String) null)),
                                StringUtils.trimToNull(jso.optString("value", (String) null)));
                        externalTextList.add(externalText);
                    }
                }

                JSONArray cvssv2Metrics = object.optJSONArray("cvss_metrics");
                List<CvssV2Metric> cvssV2MetricList = new ArrayList<>();
                if (cvssv2Metrics != null) {
                    for (int j = 0; j < cvssv2Metrics.length(); ++j) {
                        JSONObject jso = cvssv2Metrics.getJSONObject(j);
                        CvssV2Metric metric = new CvssV2Metric(jso.getInt("id"),
                                StringUtils.trimToNull(jso.optString("access_complexity", (String) null)),
                                StringUtils.trimToNull(jso.optString("cve_id", (String) null)),
                                StringUtils.trimToNull(jso.optString("source", (String) null)),
                                StringUtils.trimToNull(jso.optString("availability_impact", (String) null)),
                                StringUtils.trimToNull(jso.optString("confidentiality_impact", (String) null)),
                                StringUtils.trimToNull(jso.optString("authentication", (String) null)),
                                jso.optBigDecimal("calculated_cvss_base_score", (BigDecimal) null),
                                StringUtils.trimToNull(jso.optString("generated_on", (String) null)),
                                jso.optBigDecimal("score", (BigDecimal) null),
                                StringUtils.trimToNull(jso.optString("access_vector", (String) null)),
                                StringUtils.trimToNull(jso.optString("integrity_impact", (String) null)));
                        cvssV2MetricList.add(metric);
                    }
                }

                JSONArray cvssv3Metrics = object.optJSONArray("cvss_version_three_metrics");
                List<CvssV3Metric> cvssV3MetricList = new ArrayList<>();
                if (cvssv3Metrics != null) {
                    for (int j = 0; j < cvssv3Metrics.length(); ++j) {
                        JSONObject jso = cvssv3Metrics.getJSONObject(j);
                        CvssV3Metric metric = new CvssV3Metric(jso.getInt("id"),
                                StringUtils.trimToNull(jso.optString("attack_complexity", (String) null)),
                                jso.optString("scope", (String) null),
                                jso.optString("attack_vector", (String) null),
                                StringUtils.trimToNull(jso.optString("availability_impact", (String) null)),
                                jso.optBigDecimal("score", (BigDecimal) null),
                                StringUtils.trimToNull(jso.optString("privileges_required", (String) null)),
                                StringUtils.trimToNull(jso.optString("user_interaction", (String) null)),
                                StringUtils.trimToNull(jso.optString("cve_id", (String) null)),
                                StringUtils.trimToNull(jso.optString("source", (String) null)),
                                StringUtils.trimToNull(jso.optString("confidentiality_impact", (String) null)),
                                jso.optBigDecimal("calculated_cvss_base_score", (BigDecimal) null),
                                StringUtils.trimToNull(jso.optString("generated_on", (String) null)),
                                StringUtils.trimToNull(jso.optString("integrity_impact", (String) null))
                        );
                        cvssV3MetricList.add(metric);
                    }
                }

                JSONArray nvdInfo = object.optJSONArray("nvd_additional_information");
               // List<NvdAdditionalInfo> nvdAdditionalInfos = new ArrayList<>();
                NvdAdditionalInfo nvdAdditionalInfo = null;
                if (nvdInfo != null) {
//                    for (int j = 0; j < nvdInfo.length(); ++j) {
//                        JSONObject jso = nvdInfo.getJSONObject(j);
//                        NvdAdditionalInfo nvdAdditionalInfo = new NvdAdditionalInfo(StringUtils.trimToNull(jso.optString("summary", (String) null)),
//                                StringUtils.trimToNull(jso.optString("cwe_id", (String) null)),
//                                StringUtils.trimToNull(jso.optString("cve_id", (String) null)));
//                        nvdAdditionalInfos.add(nvdAdditionalInfo);
//                    }
                     nvdAdditionalInfo = new NvdAdditionalInfo(StringUtils.trimToNull(nvdInfo.getJSONObject(nvdInfo.length()-1).optString("summary", (String) null)),
                            StringUtils.trimToNull(nvdInfo.getJSONObject(nvdInfo.length()-1).optString("cwe_id", (String) null)),
                            StringUtils.trimToNull(nvdInfo.getJSONObject(nvdInfo.length()-1).optString("cve_id", (String) null)));

                }

                JSONArray vendors = object.optJSONArray("vendors");
                Vulnerability vulnerability = new Vulnerability(object.getInt("vulndb_id"),
                        StringUtils.trimToNull(object.optString("title", (String) null)),
                        StringUtils.trimToNull(object.optString("disclosure_date", (String) null)),
                        StringUtils.trimToNull(object.optString("discovery_date", (String) null)),
                        StringUtils.trimToNull(object.optString("exploit_publish_date", (String) null)),
                        StringUtils.trimToNull(object.optString("keywords", (String) null)),
                        StringUtils.trimToNull(object.optString("short_description", (String) null)),
                        StringUtils.trimToNull(object.optString("description", (String) null)),
                        StringUtils.trimToNull(object.optString("solution", (String) null)),
                        StringUtils.trimToNull(object.optString("manual_notes", (String) null)),
                        StringUtils.trimToNull(object.optString("t_description", (String) null)),
                        StringUtils.trimToNull(object.optString("solution_date", (String) null)),
                        StringUtils.trimToNull(object.optString("vendor_informed_date", (String) null)),
                        StringUtils.trimToNull(object.optString("vendor_ack_date", (String) null)),
                        StringUtils.trimToNull(object.optString("third_party_solution_date", (String) null)),
                        classificationList,
                        authorList,
                        externalReferenceList,
                        externalTextList,
                        this.parseVendors(vendors),
                        cvssV2MetricList,
                        cvssV3MetricList,
                        nvdAdditionalInfo
                );
                vulnerabilities.add(vulnerability);
            }
        }

        return vulnerabilities;
    }
}

