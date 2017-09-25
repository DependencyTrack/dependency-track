/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.parser.vulndb;

import alpine.logging.Logger;
import com.mashape.unirest.http.JsonNode;
import org.apache.commons.lang.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.dependencytrack.parser.vulndb.model.Author;
import org.owasp.dependencytrack.parser.vulndb.model.CPE;
import org.owasp.dependencytrack.parser.vulndb.model.Classification;
import org.owasp.dependencytrack.parser.vulndb.model.ExternalReference;
import org.owasp.dependencytrack.parser.vulndb.model.ExternalText;
import org.owasp.dependencytrack.parser.vulndb.model.Product;
import org.owasp.dependencytrack.parser.vulndb.model.Results;
import org.owasp.dependencytrack.parser.vulndb.model.Vendor;
import org.owasp.dependencytrack.parser.vulndb.model.Version;
import org.owasp.dependencytrack.parser.vulndb.model.Vulnerability;
import java.util.ArrayList;
import java.util.List;

public class VulnDbParser {

    private static final Logger LOGGER = Logger.getLogger(VulnDbParser.class);

    public Results parse(JsonNode jsonNode, Class resultType) {
        LOGGER.debug("Parsing JSON node");

        final Results results = new Results();
        final JSONObject root = jsonNode.getObject();
        results.setPage(root.getInt("current_page"));
        results.setTotal(root.getInt("total_entries"));
        final JSONArray rso = root.getJSONArray("results");

        if (Product.class == resultType) {
            results.setResults(parseProducts(rso));
        } else if (Vendor.class == resultType) {
            results.setResults(parseVendors(rso));
        } else if (Version.class == resultType) {
            results.setResults(parseVersions(rso));
        } else if (Vulnerability.class == resultType) {
            results.setResults(parseVulnerabilities(rso));
        }
        return results;
    }

    private List<CPE> parseCpes(JSONArray rso) {
        List<CPE> cpes = null;
        if (rso != null) {
            cpes = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final CPE cpe = new CPE();
                cpe.setCpe(StringUtils.trimToNull(object.optString("cpe", null)));
                cpe.setType(StringUtils.trimToNull(object.optString("type", null)));
                cpes.add(cpe);
            }
        }
        return cpes;
    }

    private List<Product> parseProducts(JSONArray rso) {
        List<Product> products = null;
        if (rso != null) {
            products = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final Product product = new Product();
                product.setId(object.getInt("id"));
                product.setName(StringUtils.trimToNull(object.optString("name", null)));
                product.setVersions(parseVersions(object.optJSONArray("versions")));
                products.add(product);
            }
        }
        return products;
    }

    private List<Vendor> parseVendors(JSONArray rso) {
        List<Vendor> vendors = null;
        if (rso != null) {
            vendors = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final Vendor vendor = new Vendor();
                vendor.setId(object.getInt("id"));
                vendor.setName(StringUtils.trimToNull(object.optString("name", null)));
                vendor.setShortName(StringUtils.trimToNull(object.optString("short_name", null)));
                vendor.setVendorUrl(StringUtils.trimToNull(object.optString("vendor_url", null)));
                vendor.setProducts(parseProducts(object.optJSONArray("products")));
                vendors.add(vendor);
            }
        }
        return vendors;
    }

    private List<Version> parseVersions(JSONArray rso) {
        List<Version> versions = null;
        if (rso != null) {
            versions = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final Version version = new Version();
                version.setId(object.getInt("id"));
                version.setName(StringUtils.trimToNull(object.optString("name", null)));
                version.setAffected(object.optBoolean("affected", false));
                version.setCpes(parseCpes(object.optJSONArray("cpe")));
                versions.add(version);
            }
        }
        return versions;
    }

    private List<Vulnerability> parseVulnerabilities(JSONArray rso) {
        List<Vulnerability> vulnerabilities = null;
        if (rso != null) {
            vulnerabilities = new ArrayList<>();
            for (int i = 0; i < rso.length(); i++) {
                final JSONObject object = rso.getJSONObject(i);
                final Vulnerability vulnerability = new Vulnerability();
                vulnerability.setVulnDbId(object.getInt("vulndb_id"));
                vulnerability.setTitle(StringUtils.trimToNull(object.optString("title", null)));
                vulnerability.setDisclosureDate(StringUtils.trimToNull(object.optString("disclosure_date", null)));
                vulnerability.setDiscoveryDate(StringUtils.trimToNull(object.optString("discovery_date", null)));
                vulnerability.setExploitPublishDate(StringUtils.trimToNull(object.optString("exploit_publish_date", null)));
                vulnerability.setKeywords(StringUtils.trimToNull(object.optString("keywords", null)));
                vulnerability.setShortDescription(StringUtils.trimToNull(object.optString("short_description", null)));
                vulnerability.setDescription(StringUtils.trimToNull(object.optString("description", null)));
                vulnerability.setSolution(StringUtils.trimToNull(object.optString("solution", null)));
                vulnerability.setManualNotes(StringUtils.trimToNull(object.optString("manual_notes", null)));
                vulnerability.setTechnicalDescription(StringUtils.trimToNull(object.optString("t_description", null)));
                vulnerability.setSolutionDate(StringUtils.trimToNull(object.optString("solution_date", null)));
                vulnerability.setVendorInformedDate(StringUtils.trimToNull(object.optString("vendor_informed_date", null)));
                vulnerability.setVendorAckDate(StringUtils.trimToNull(object.optString("vendor_ack_date", null)));
                vulnerability.setThirdPartySolutionDate(StringUtils.trimToNull(object.optString("third_party_solution_date", null)));

                final JSONArray classifications = object.optJSONArray("classifications");
                if (classifications != null) {
                    for (int j = 0; j < classifications.length(); j++) {
                        final JSONObject jso = classifications.getJSONObject(j);
                        final Classification classification = new Classification();
                        classification.setId(jso.getInt("id"));
                        classification.setName(StringUtils.trimToNull(jso.optString("name", null)));
                        classification.setLongname(StringUtils.trimToNull(jso.optString("longname", null)));
                        classification.setDescription(StringUtils.trimToNull(jso.optString("description", null)));
                        classification.setMediumtext(StringUtils.trimToNull(jso.optString("mediumtext", null)));
                        vulnerability.addClassifications(classification);
                    }
                }

                final JSONArray authors = object.optJSONArray("authors");
                if (authors != null) {
                    for (int j = 0; j < authors.length(); j++) {
                        final JSONObject jso = authors.getJSONObject(j);
                        final Author author = new Author();
                        author.setId(jso.getInt("id"));
                        author.setName(StringUtils.trimToNull(jso.optString("name", null)));
                        author.setCompany(StringUtils.trimToNull(jso.optString("company", null)));
                        author.setEmail(StringUtils.trimToNull(jso.optString("email", null)));
                        author.setCompanyUrl(StringUtils.trimToNull(jso.optString("company_url", null)));
                        author.setCountry(StringUtils.trimToNull(jso.optString("country", null)));
                        vulnerability.addAuthor(author);
                    }
                }

                final JSONArray extRefs = object.optJSONArray("ext_references");
                if (extRefs != null) {
                    for (int j = 0; j < extRefs.length(); j++) {
                        final JSONObject jso = extRefs.getJSONObject(j);
                        final ExternalReference externalReference = new ExternalReference();
                        externalReference.setType(StringUtils.trimToNull(jso.optString("type", null)));
                        externalReference.setValue(StringUtils.trimToNull(jso.optString("value", null)));
                        vulnerability.addExtReference(externalReference);
                    }
                }

                final JSONArray extTexts = object.optJSONArray("ext_texts");
                if (extTexts != null) {
                    for (int j = 0; j < extTexts.length(); j++) {
                        final JSONObject jso = extTexts.getJSONObject(j);
                        final ExternalText externalText = new ExternalText();
                        externalText.setType(StringUtils.trimToNull(jso.optString("type", null)));
                        externalText.setValue(StringUtils.trimToNull(jso.optString("value", null)));
                        vulnerability.addExtText(externalText);
                    }
                }

                final JSONArray vendors = object.optJSONArray("vendors");
                vulnerability.setVendors(parseVendors(vendors));

                vulnerabilities.add(vulnerability);
            }
        }
        return vulnerabilities;
    }

}
