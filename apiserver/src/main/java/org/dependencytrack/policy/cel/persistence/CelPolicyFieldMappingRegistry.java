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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.policy.cel.persistence;

import java.util.Collection;
import java.util.List;

public final class CelPolicyFieldMappingRegistry {

    private CelPolicyFieldMappingRegistry() {
    }

    public record FieldMapping(String protoFieldName, String sqlExpression) {
    }

    static final List<FieldMapping> COMPONENT_FIELDS = List.of(
            new FieldMapping("uuid", "c.\"UUID\""),
            new FieldMapping("group", "c.\"GROUP\""),
            new FieldMapping("name", "c.\"NAME\""),
            new FieldMapping("version", "c.\"VERSION\""),
            new FieldMapping("classifier", "c.\"CLASSIFIER\""),
            new FieldMapping("cpe", "c.\"CPE\""),
            new FieldMapping("purl", "c.\"PURL\""),
            new FieldMapping("swid_tag_id", "c.\"SWIDTAGID\""),
            new FieldMapping("is_internal", "c.\"INTERNAL\""),
            new FieldMapping("is_direct", "c.\"DIRECT\""),
            new FieldMapping("md5", "c.\"MD5\""),
            new FieldMapping("sha1", "c.\"SHA1\""),
            new FieldMapping("sha256", "c.\"SHA_256\""),
            new FieldMapping("sha384", "c.\"SHA_384\""),
            new FieldMapping("sha512", "c.\"SHA_512\""),
            new FieldMapping("sha3_256", "c.\"SHA3_256\""),
            new FieldMapping("sha3_384", "c.\"SHA3_384\""),
            new FieldMapping("sha3_512", "c.\"SHA3_512\""),
            new FieldMapping("blake2b_256", "c.\"BLAKE2B_256\""),
            new FieldMapping("blake2b_384", "c.\"BLAKE2B_384\""),
            new FieldMapping("blake2b_512", "c.\"BLAKE2B_512\""),
            new FieldMapping("blake3", "c.\"BLAKE3\""),
            new FieldMapping("license_name", "c.\"LICENSE\""),
            new FieldMapping("license_expression", "c.\"LICENSE_EXPRESSION\""),
            new FieldMapping("published_at", "pam.\"PUBLISHED_AT\""),
            new FieldMapping("latest_version", "pm.\"LATEST_VERSION\""));

    static final List<FieldMapping> COMPONENT_PROPERTY_FIELDS = List.of(
            new FieldMapping("group", "cp.\"GROUPNAME\""),
            new FieldMapping("name", "cp.\"PROPERTYNAME\""),
            new FieldMapping("value", "cp.\"PROPERTYVALUE\""),
            new FieldMapping("type", "cp.\"PROPERTYTYPE\""));

    static final List<FieldMapping> VULNERABILITY_FIELDS = List.of(
            new FieldMapping("uuid", "v.\"UUID\""),
            new FieldMapping("id", "v.\"VULNID\""),
            new FieldMapping("source", "v.\"SOURCE\""),
            new FieldMapping("created", "v.\"CREATED\""),
            new FieldMapping("published", "v.\"PUBLISHED\""),
            new FieldMapping("updated", "v.\"UPDATED\""),
            new FieldMapping("severity", "v.\"SEVERITY\""),
            new FieldMapping("cvssv2_base_score", "v.\"CVSSV2BASESCORE\""),
            new FieldMapping("cvssv2_impact_subscore", "v.\"CVSSV2IMPACTSCORE\""),
            new FieldMapping("cvssv2_exploitability_subscore", "v.\"CVSSV2EXPLOITSCORE\""),
            new FieldMapping("cvssv2_vector", "v.\"CVSSV2VECTOR\""),
            new FieldMapping("cvssv3_base_score", "v.\"CVSSV3BASESCORE\""),
            new FieldMapping("cvssv3_impact_subscore", "v.\"CVSSV3IMPACTSCORE\""),
            new FieldMapping("cvssv3_exploitability_subscore", "v.\"CVSSV3EXPLOITSCORE\""),
            new FieldMapping("cvssv3_vector", "v.\"CVSSV3VECTOR\""),
            new FieldMapping("cvssv4_score", "v.\"CVSSV4SCORE\""),
            new FieldMapping("cvssv4_vector", "v.\"CVSSV4VECTOR\""),
            new FieldMapping("owasp_rr_likelihood_score", "v.\"OWASPRRLIKELIHOODSCORE\""),
            new FieldMapping("owasp_rr_technical_impact_score", "v.\"OWASPRRTECHNICALIMPACTSCORE\""),
            new FieldMapping("owasp_rr_business_impact_score", "v.\"OWASPRRBUSINESSIMPACTSCORE\""),
            new FieldMapping("owasp_rr_vector", "v.\"OWASPRRVECTOR\""),
            new FieldMapping("cwes", "STRING_TO_ARRAY(v.\"CWES\", ',')"),
            new FieldMapping("aliases", "CAST(JSONB_VULN_ALIASES(v.\"SOURCE\", v.\"VULNID\") AS TEXT)"),
            new FieldMapping("epss_score", "ep.\"SCORE\""),
            new FieldMapping("epss_percentile", "ep.\"PERCENTILE\""));

    static final List<FieldMapping> LICENSE_FIELDS = List.of(
            new FieldMapping("uuid", "l.\"UUID\""),
            new FieldMapping("id", "l.\"LICENSEID\""),
            new FieldMapping("name", "l.\"NAME\""),
            new FieldMapping("is_osi_approved", "l.\"ISOSIAPPROVED\""),
            new FieldMapping("is_fsf_libre", "l.\"FSFLIBRE\""),
            new FieldMapping("is_deprecated_id", "l.\"ISDEPRECATED\""),
            new FieldMapping("is_custom", "l.\"ISCUSTOMLICENSE\""));

    static final List<FieldMapping> LICENSE_GROUP_FIELDS = List.of(
            new FieldMapping("uuid", "lg.\"UUID\""),
            new FieldMapping("name", "lg.\"NAME\""));

    static final List<FieldMapping> PROJECT_FIELDS = List.of(
            new FieldMapping("uuid", "p.\"UUID\""),
            new FieldMapping("group", "p.\"GROUP\""),
            new FieldMapping("name", "p.\"NAME\""),
            new FieldMapping("version", "p.\"VERSION\""),
            new FieldMapping("classifier", "p.\"CLASSIFIER\""),
            new FieldMapping("cpe", "p.\"CPE\""),
            new FieldMapping("purl", "p.\"PURL\""),
            new FieldMapping("swid_tag_id", "p.\"SWIDTAGID\""),
            new FieldMapping("last_bom_import", "p.\"LAST_BOM_IMPORTED\""),
            new FieldMapping("metadata_tools", "pm.\"TOOLS\""),
            new FieldMapping("bom_generated", "b.\"GENERATED\""),
            new FieldMapping("inactive_since", "p.\"INACTIVE_SINCE\""));

    static final List<FieldMapping> PROJECT_PROPERTY_FIELDS = List.of(
            new FieldMapping("group", "pp.\"GROUPNAME\""),
            new FieldMapping("name", "pp.\"PROPERTYNAME\""),
            new FieldMapping("value", "pp.\"PROPERTYVALUE\""),
            new FieldMapping("type", "pp.\"PROPERTYTYPE\""));

    static List<String> selectColumns(
            List<FieldMapping> fields,
            Collection<String> requiredProtoFields) {
        return fields.stream()
                .filter(fieldMapping -> requiredProtoFields.contains(fieldMapping.protoFieldName()))
                .map(fieldMapping -> fieldMapping.sqlExpression() + " AS \"" + fieldMapping.protoFieldName() + "\"")
                .toList();
    }

}
