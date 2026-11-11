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
package org.dependencytrack.tasks;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedEpochRandomGenerator;
import org.apache.commons.lang3.SerializationUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.Scope;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.persistence.converter.OrganizationalContactsJsonConverter;
import org.dependencytrack.persistence.converter.OrganizationalEntityJsonConverter;
import org.dependencytrack.persistence.converter.ToolsJsonConverter;
import org.dependencytrack.persistence.jdbi.ComponentLicenseDao;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Gatherers;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;
import static org.dependencytrack.support.jdbi.binding.Bindings.columnValues;

/// @since 5.3.0
@NullMarked
final class BomImportDao {

    record ExistingComponentRow(long id, UUID uuid, ComponentIdentity identity) {}

    record ExistingServiceRow(long id, UUID uuid, ComponentIdentity identity) {}

    sealed interface ComponentOwnedRow<I, K> {

        I id();

        long componentId();

        K identity();
    }

    record ExistingComponentPropertyRow(Long id, long componentId, ComponentProperty.Identity identity)
            implements ComponentOwnedRow<Long, ComponentProperty.Identity> {}

    record ExistingComponentLicenseRow(Long id, long componentId, ComponentLicenseDao.ComponentLicenseRow identity)
            implements ComponentOwnedRow<Long, ComponentLicenseDao.ComponentLicenseRow> {}

    record ExistingComponentOccurrenceRow(UUID id, long componentId, ComponentOccurrence.Identity identity)
            implements ComponentOwnedRow<UUID, ComponentOccurrence.Identity> {}

    private static final int BATCH_SIZE = 1000;
    private static final OrganizationalContactsJsonConverter CONTACTS_CONVERTER =
            new OrganizationalContactsJsonConverter();
    private static final OrganizationalEntityJsonConverter ENTITY_CONVERTER = new OrganizationalEntityJsonConverter();
    private static final ToolsJsonConverter TOOLS_CONVERTER = new ToolsJsonConverter();
    private static final TimeBasedEpochRandomGenerator UUIDV7_GENERATOR = Generators.timeBasedEpochRandomGenerator();

    private final Handle handle;

    BomImportDao(Handle handle) {
        this.handle = handle;
    }

    void upsertProjectMetadata(long projectId, ProjectMetadata metadata) {
        handle.createUpdate(/* language=SQL */ """
            INSERT INTO "PROJECT_METADATA" AS meta (
              "PROJECT_ID"
            , "SUPPLIER"
            , "AUTHORS"
            , "TOOLS"
            )
            VALUES (:projectId, :supplier, :authors, :tools)
            ON CONFLICT ("PROJECT_ID") DO UPDATE
            SET "SUPPLIER" = EXCLUDED."SUPPLIER"
              , "AUTHORS" = EXCLUDED."AUTHORS"
              , "TOOLS" = EXCLUDED."TOOLS"
            WHERE (meta."SUPPLIER", meta."AUTHORS", meta."TOOLS")
                  IS DISTINCT FROM (EXCLUDED."SUPPLIER", EXCLUDED."AUTHORS", EXCLUDED."TOOLS")
            """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#upsertProjectMetadata".formatted(getClass().getSimpleName()))
                .bind("projectId", projectId)
                .bind("supplier", ENTITY_CONVERTER.convertToDatastore(metadata.getSupplier()))
                .bind("authors", CONTACTS_CONVERTER.convertToDatastore(metadata.getAuthors()))
                .bind("tools", TOOLS_CONVERTER.convertToDatastore(metadata.getTools()))
                .execute();
    }

    void updateProject(long projectId, Project bomProject) {
        handle.createUpdate(/* language=SQL */ """
            UPDATE "PROJECT"
               SET "AUTHORS" = :authors
                 , "PUBLISHER" = :publisher
                 , "CLASSIFIER" = :classifier
                 , "SUPPLIER" = :supplier
                 , "MANUFACTURER" = :manufacturer
                 , "EXTERNAL_REFERENCES" = :externalReferences
                 , "CPE" = :cpe
                 , "PURL" = :purl
                 , "SWIDTAGID" = :swidTagId
             WHERE "ID" = :projectId
            """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#updateProject".formatted(getClass().getSimpleName()))
                .bind("projectId", projectId)
                .bind("authors", CONTACTS_CONVERTER.convertToDatastore(bomProject.getAuthors()))
                .bind("publisher", bomProject.getPublisher())
                .bind("classifier", Objects.toString(bomProject.getClassifier(), null))
                .bind("supplier", ENTITY_CONVERTER.convertToDatastore(bomProject.getSupplier()))
                .bind("manufacturer", ENTITY_CONVERTER.convertToDatastore(bomProject.getManufacturer()))
                .bind("externalReferences", serialize(bomProject.getExternalReferences()))
                .bind("cpe", bomProject.getCpe())
                .bind("purl", Objects.toString(bomProject.getPurl(), null))
                .bind("swidTagId", bomProject.getSwidTagId())
                .execute();
    }

    long recordBomImport(
            long projectId,
            @Nullable String directDependencies,
            String format,
            @Nullable String specVersion,
            @Nullable String serialNumber,
            @Nullable Integer bomVersion,
            @Nullable Date generated,
            byte @Nullable [] originalFileMetadata) {
        return handle.createQuery(/* language=SQL */ """
            WITH imported_bom AS (
              INSERT INTO "BOM" (
                "PROJECT_ID"
              , "UUID"
              , "BOM_FORMAT"
              , "SPEC_VERSION"
              , "SERIAL_NUMBER"
              , "BOM_VERSION"
              , "IMPORTED"
              , "GENERATED"
              , "ORIGINAL_FILE_METADATA"
              )
              VALUES (
                :projectId
              , GEN_RANDOM_UUID()
              , :format
              , :specVersion
              , :serialNumber
              , :bomVersion
              , :imported
              , :generated
              , :originalFileMetadata
              )
              RETURNING "ID"
            )
            UPDATE "PROJECT"
               SET "DIRECT_DEPENDENCIES" = CAST(:directDependencies AS JSONB)
                 , "LAST_BOM_IMPORTED" = :imported
                 , "LAST_BOM_IMPORTED_FORMAT" = :importedFormat
             WHERE "ID" = :projectId
             RETURNING (SELECT "ID" FROM imported_bom)
            """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#recordBomImport".formatted(getClass().getSimpleName()))
                .bind("projectId", projectId)
                .bind("directDependencies", directDependencies)
                .bind("format", format)
                .bind("specVersion", specVersion)
                .bind("serialNumber", serialNumber)
                .bind("bomVersion", bomVersion)
                .bind("imported", new Date())
                .bind("generated", generated)
                .bind("importedFormat", "%s %s".formatted(format, specVersion))
                .bind("originalFileMetadata", originalFileMetadata)
                .mapTo(Long.class)
                .one();
    }

    Map<String, Long> getLicenseIdsByIdOrName(Collection<String> idsOrNames) {
        if (idsOrNames.isEmpty()) {
            return Map.of();
        }

        // Multiple licenses can share a name, in which case the one with the lowest license ID wins.
        return handle.createQuery(/* language=SQL */ """
            SELECT DISTINCT ON (t.id_or_name)
                   t.id_or_name
                 , lic."ID"
              FROM UNNEST(:idsOrNames) AS t(id_or_name)
             INNER JOIN "LICENSE" AS lic
                ON lic."LICENSEID" = t.id_or_name
                OR lic."NAME" = t.id_or_name
             ORDER BY t.id_or_name
                    , lic."LICENSEID"
            """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#getLicenseIdsByIdOrName".formatted(getClass().getSimpleName()))
                .bindArray("idsOrNames", String.class, idsOrNames)
                .map((rs, _) -> Map.entry(rs.getString("id_or_name"), rs.getLong("ID")))
                .collectToMap(Map.Entry::getKey, Map.Entry::getValue);
    }

    List<ExistingComponentRow> getExistingComponents(long projectId) {
        return handle.createQuery(/* language=SQL */ """
            SELECT "ID"
                 , "UUID"
                 , "GROUP"
                 , "NAME"
                 , "VERSION"
                 , "PURL"
                 , "CPE"
                 , "SWIDTAGID"
                 , "SCOPE"
              FROM "COMPONENT"
             WHERE "PROJECT_ID" = :projectId
            """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#getExistingComponents".formatted(getClass().getSimpleName()))
                .bind("projectId", projectId)
                .map((rs, _) -> {
                    final var component = new Component();
                    component.setGroup(rs.getString("GROUP"));
                    component.setName(rs.getString("NAME"));
                    component.setVersion(rs.getString("VERSION"));
                    component.setPurl(rs.getString("PURL"));
                    component.setCpe(rs.getString("CPE"));
                    component.setSwidTagId(rs.getString("SWIDTAGID"));
                    final String scope = rs.getString("SCOPE");
                    component.setScope(scope != null ? Scope.valueOf(scope) : null);
                    return new ExistingComponentRow(
                            rs.getLong("ID"), rs.getObject("UUID", UUID.class), new ComponentIdentity(component));
                })
                .list();
    }

    void createComponents(long projectId, Collection<Component> components) throws InterruptedException {
        inBatches(components, batch -> {
            final Update insert = handle.createUpdate(/* language=SQL */ """
                INSERT INTO "COMPONENT" (
                  "PROJECT_ID"
                , "LAST_RISKSCORE"
                , "UUID"
                , "AUTHORS"
                , "PUBLISHER"
                , "SUPPLIER"
                , "CLASSIFIER"
                , "GROUP"
                , "NAME"
                , "VERSION"
                , "DESCRIPTION"
                , "COPYRIGHT"
                , "CPE"
                , "PURL"
                , "PURLCOORDINATES"
                , "SWIDTAGID"
                , "MD5"
                , "SHA1"
                , "SHA_256"
                , "SHA_384"
                , "SHA_512"
                , "SHA3_256"
                , "SHA3_384"
                , "SHA3_512"
                , "BLAKE2B_256"
                , "BLAKE2B_384"
                , "BLAKE2B_512"
                , "BLAKE3"
                , "STREEBOG_256"
                , "STREEBOG_512"
                , "LICENSE_ID"
                , "LICENSE"
                , "LICENSE_URL"
                , "LICENSE_EXPRESSION"
                , "INTERNAL"
                , "EXTERNAL_REFERENCES"
                , "SCOPE"
                , "DIRECT_DEPENDENCIES"
                )
                SELECT :projectId
                     , 0
                     , t.*
                  FROM UNNEST(
                    :uuids
                  , :authors
                  , :publishers
                  , :suppliers
                  , :classifiers
                  , :groups
                  , :names
                  , :versions
                  , :descriptions
                  , :copyrights
                  , :cpes
                  , :purls
                  , :purlCoordinates
                  , :swidTagIds
                  , :md5s
                  , :sha1s
                  , :sha256s
                  , :sha384s
                  , :sha512s
                  , :sha3_256s
                  , :sha3_384s
                  , :sha3_512s
                  , :blake2b_256s
                  , :blake2b_384s
                  , :blake2b_512s
                  , :blake3s
                  , :streebog_256s
                  , :streebog_512s
                  , :licenseIds
                  , :licenses
                  , :licenseUrls
                  , :licenseExpressions
                  , :internals
                  , :externalReferences
                  , :scopes
                  , CAST(:directDependencies AS JSONB[])
                  ) AS t
                RETURNING "ID"
                        , "UUID"
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#createComponents".formatted(getClass().getSimpleName()))
                    .bind("projectId", projectId)
                    .bindArray("uuids", UUID.class, columnValues(batch, Component::getUuid));
            bindComponentColumns(insert, batch);

            final Map<UUID, Long> idByUuid = insert.executeAndReturnGeneratedKeys()
                    .map((rs, _) -> Map.entry(rs.getObject("UUID", UUID.class), rs.getLong("ID")))
                    .collectToMap(Map.Entry::getKey, Map.Entry::getValue);

            for (final Component component : batch) {
                component.setId(requireNonNull(idByUuid.get(component.getUuid()), "id must not be null"));
            }
        });
    }

    void updateComponents(Collection<Component> components) throws InterruptedException {
        // Lock rows in ID order to avoid deadlocks with concurrent analysis and metrics updates.
        final List<Component> componentsById = components.stream()
                .sorted(Comparator.comparingLong(Component::getId))
                .toList();
        inBatches(componentsById, batch -> {
            final Update update = handle.createUpdate(/* language=SQL */ """
                UPDATE "COMPONENT" AS cmp
                   SET "AUTHORS" = t.authors
                     , "PUBLISHER" = t.publisher
                     , "SUPPLIER" = t.supplier
                     , "CLASSIFIER" = t.classifier
                     , "GROUP" = t.group_name
                     , "NAME" = t.name
                     , "VERSION" = t.version
                     , "DESCRIPTION" = t.description
                     , "COPYRIGHT" = t.copyright
                     , "CPE" = t.cpe
                     , "PURL" = t.purl
                     , "PURLCOORDINATES" = t.purl_coordinates
                     , "SWIDTAGID" = t.swid_tag_id
                     , "MD5" = t.md5
                     , "SHA1" = t.sha1
                     , "SHA_256" = t.sha_256
                     , "SHA_384" = t.sha_384
                     , "SHA_512" = t.sha_512
                     , "SHA3_256" = t.sha3_256
                     , "SHA3_384" = t.sha3_384
                     , "SHA3_512" = t.sha3_512
                     , "BLAKE2B_256" = t.blake2b_256
                     , "BLAKE2B_384" = t.blake2b_384
                     , "BLAKE2B_512" = t.blake2b_512
                     , "BLAKE3" = t.blake3
                     , "STREEBOG_256" = t.streebog_256
                     , "STREEBOG_512" = t.streebog_512
                     , "LICENSE_ID" = t.license_id
                     , "LICENSE" = t.license
                     , "LICENSE_URL" = t.license_url
                     , "LICENSE_EXPRESSION" = t.license_expression
                     , "INTERNAL" = t.internal
                     , "EXTERNAL_REFERENCES" = t.external_references
                     , "SCOPE" = t.scope
                     , "DIRECT_DEPENDENCIES" = t.direct_dependencies
                  FROM UNNEST(
                    :ids
                  , :authors
                  , :publishers
                  , :suppliers
                  , :classifiers
                  , :groups
                  , :names
                  , :versions
                  , :descriptions
                  , :copyrights
                  , :cpes
                  , :purls
                  , :purlCoordinates
                  , :swidTagIds
                  , :md5s
                  , :sha1s
                  , :sha256s
                  , :sha384s
                  , :sha512s
                  , :sha3_256s
                  , :sha3_384s
                  , :sha3_512s
                  , :blake2b_256s
                  , :blake2b_384s
                  , :blake2b_512s
                  , :blake3s
                  , :streebog_256s
                  , :streebog_512s
                  , :licenseIds
                  , :licenses
                  , :licenseUrls
                  , :licenseExpressions
                  , :internals
                  , :externalReferences
                  , :scopes
                  , CAST(:directDependencies AS JSONB[])
                  ) AS t(
                    id
                  , authors
                  , publisher
                  , supplier
                  , classifier
                  , group_name
                  , name
                  , version
                  , description
                  , copyright
                  , cpe
                  , purl
                  , purl_coordinates
                  , swid_tag_id
                  , md5
                  , sha1
                  , sha_256
                  , sha_384
                  , sha_512
                  , sha3_256
                  , sha3_384
                  , sha3_512
                  , blake2b_256
                  , blake2b_384
                  , blake2b_512
                  , blake3
                  , streebog_256
                  , streebog_512
                  , license_id
                  , license
                  , license_url
                  , license_expression
                  , internal
                  , external_references
                  , scope
                  , direct_dependencies
                  )
                 WHERE cmp."ID" = t.id
                   AND (
                     cmp."AUTHORS"
                   , cmp."PUBLISHER"
                   , cmp."SUPPLIER"
                   , cmp."CLASSIFIER"
                   , cmp."GROUP"
                   , cmp."NAME"
                   , cmp."VERSION"
                   , cmp."DESCRIPTION"
                   , cmp."COPYRIGHT"
                   , cmp."CPE"
                   , cmp."PURL"
                   , cmp."PURLCOORDINATES"
                   , cmp."SWIDTAGID"
                   , cmp."MD5"
                   , cmp."SHA1"
                   , cmp."SHA_256"
                   , cmp."SHA_384"
                   , cmp."SHA_512"
                   , cmp."SHA3_256"
                   , cmp."SHA3_384"
                   , cmp."SHA3_512"
                   , cmp."BLAKE2B_256"
                   , cmp."BLAKE2B_384"
                   , cmp."BLAKE2B_512"
                   , cmp."BLAKE3"
                   , cmp."STREEBOG_256"
                   , cmp."STREEBOG_512"
                   , cmp."LICENSE_ID"
                   , cmp."LICENSE"
                   , cmp."LICENSE_URL"
                   , cmp."LICENSE_EXPRESSION"
                   , cmp."INTERNAL"
                   , cmp."EXTERNAL_REFERENCES"
                   , cmp."SCOPE"
                   , cmp."DIRECT_DEPENDENCIES"
                   ) IS DISTINCT FROM (
                     t.authors
                   , t.publisher
                   , t.supplier
                   , t.classifier
                   , t.group_name
                   , t.name
                   , t.version
                   , t.description
                   , t.copyright
                   , t.cpe
                   , t.purl
                   , t.purl_coordinates
                   , t.swid_tag_id
                   , t.md5
                   , t.sha1
                   , t.sha_256
                   , t.sha_384
                   , t.sha_512
                   , t.sha3_256
                   , t.sha3_384
                   , t.sha3_512
                   , t.blake2b_256
                   , t.blake2b_384
                   , t.blake2b_512
                   , t.blake3
                   , t.streebog_256
                   , t.streebog_512
                   , t.license_id
                   , t.license
                   , t.license_url
                   , t.license_expression
                   , t.internal
                   , t.external_references
                   , t.scope
                   , t.direct_dependencies
                   )
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#updateComponents".formatted(getClass().getSimpleName()))
                    .bindArray("ids", Long.class, columnValues(batch, Component::getId));
            bindComponentColumns(update, batch);
            update.execute();
        });
    }

    void deleteComponents(Collection<Long> ids) throws InterruptedException {
        // Lock rows in ID order to avoid deadlocks with concurrent analysis and metrics updates.
        inBatches(ids.stream().sorted().toList(), batch -> {
            handle.createUpdate(/* language=SQL */ """
                DELETE
                  FROM "COMPONENT"
                 WHERE "ID" = ANY(:ids)
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#deleteComponents".formatted(getClass().getSimpleName()))
                    .bindArray("ids", Long.class, batch)
                    .execute();
        });
    }

    List<ExistingServiceRow> getExistingServices(long projectId) {
        return handle.createQuery(/* language=SQL */ """
            SELECT "ID"
                 , "UUID"
                 , "GROUP"
                 , "NAME"
                 , "VERSION"
              FROM "SERVICECOMPONENT"
             WHERE "PROJECT_ID" = :projectId
            """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#getExistingServices".formatted(getClass().getSimpleName()))
                .bind("projectId", projectId)
                .map((rs, _) -> {
                    final var service = new ServiceComponent();
                    service.setGroup(rs.getString("GROUP"));
                    service.setName(rs.getString("NAME"));
                    service.setVersion(rs.getString("VERSION"));
                    return new ExistingServiceRow(
                            rs.getLong("ID"), rs.getObject("UUID", UUID.class), new ComponentIdentity(service));
                })
                .list();
    }

    void createServices(long projectId, Collection<ServiceComponent> services) throws InterruptedException {
        inBatches(services, batch -> {
            final Update insert = handle.createUpdate(/* language=SQL */ """
                INSERT INTO "SERVICECOMPONENT" (
                  "PROJECT_ID"
                , "UUID"
                , "GROUP"
                , "NAME"
                , "VERSION"
                , "DESCRIPTION"
                , "AUTHENTICATED"
                , "X_TRUST_BOUNDARY"
                , "EXTERNAL_REFERENCES"
                , "PROVIDER_ID"
                , "DATA"
                , "ENDPOINTS"
                )
                SELECT :projectId
                     , t.*
                  FROM UNNEST(
                    :uuids
                  , :groups
                  , :names
                  , :versions
                  , :descriptions
                  , :authenticated
                  , :crossesTrustBoundary
                  , :externalReferences
                  , :providers
                  , :data
                  , :endpoints
                  ) AS t
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#createServices".formatted(getClass().getSimpleName()))
                    .bind("projectId", projectId)
                    .bindArray("uuids", UUID.class, columnValues(batch, ServiceComponent::getUuid));
            bindServiceColumns(insert, batch);
            insert.execute();
        });
    }

    void updateServices(Collection<ServiceComponent> services) throws InterruptedException {
        // Lock rows in ID order to avoid deadlocks with concurrent writers.
        final List<ServiceComponent> servicesById = services.stream()
                .sorted(Comparator.comparingLong(ServiceComponent::getId))
                .toList();
        inBatches(servicesById, batch -> {
            final Update update = handle.createUpdate(/* language=SQL */ """
                UPDATE "SERVICECOMPONENT" AS svc
                   SET "GROUP" = t.group_name
                     , "NAME" = t.name
                     , "VERSION" = t.version
                     , "DESCRIPTION" = t.description
                     , "AUTHENTICATED" = t.authenticated
                     , "X_TRUST_BOUNDARY" = t.crosses_trust_boundary
                     , "EXTERNAL_REFERENCES" = t.external_references
                     , "PROVIDER_ID" = t.provider
                     , "DATA" = t.data
                     , "ENDPOINTS" = t.endpoints
                  FROM UNNEST(
                    :ids
                  , :groups
                  , :names
                  , :versions
                  , :descriptions
                  , :authenticated
                  , :crossesTrustBoundary
                  , :externalReferences
                  , :providers
                  , :data
                  , :endpoints
                  ) AS t(
                    id
                  , group_name
                  , name
                  , version
                  , description
                  , authenticated
                  , crosses_trust_boundary
                  , external_references
                  , provider
                  , data
                  , endpoints
                  )
                 WHERE svc."ID" = t.id
                   AND (
                     svc."GROUP"
                   , svc."NAME"
                   , svc."VERSION"
                   , svc."DESCRIPTION"
                   , svc."AUTHENTICATED"
                   , svc."X_TRUST_BOUNDARY"
                   , svc."EXTERNAL_REFERENCES"
                   , svc."PROVIDER_ID"
                   , svc."DATA"
                   , svc."ENDPOINTS"
                   ) IS DISTINCT FROM (
                     t.group_name
                   , t.name
                   , t.version
                   , t.description
                   , t.authenticated
                   , t.crosses_trust_boundary
                   , t.external_references
                   , t.provider
                   , t.data
                   , t.endpoints
                   )
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#updateServices".formatted(getClass().getSimpleName()))
                    .bindArray("ids", Long.class, columnValues(batch, ServiceComponent::getId));
            bindServiceColumns(update, batch);
            update.execute();
        });
    }

    void deleteServices(Collection<Long> ids) throws InterruptedException {
        inBatches(ids, batch -> {
            handle.createUpdate(/* language=SQL */ """
                DELETE
                  FROM "SERVICECOMPONENT"
                 WHERE "ID" = ANY(:ids)
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#deleteServices".formatted(getClass().getSimpleName()))
                    .bindArray("ids", Long.class, batch)
                    .execute();
        });
    }

    List<ExistingComponentPropertyRow> getComponentProperties(long projectId) {
        return handle.createQuery(/* language=SQL */ """
            SELECT prop."ID"
                 , prop."COMPONENT_ID"
                 , prop."GROUPNAME"
                 , prop."PROPERTYNAME"
                 , prop."PROPERTYVALUE"
              FROM "COMPONENT_PROPERTY" AS prop
             INNER JOIN "COMPONENT" AS cmp
                ON cmp."ID" = prop."COMPONENT_ID"
             WHERE cmp."PROJECT_ID" = :projectId
            """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#getComponentProperties".formatted(getClass().getSimpleName()))
                .bind("projectId", projectId)
                .map((rs, _) -> new ExistingComponentPropertyRow(
                        rs.getLong("ID"),
                        rs.getLong("COMPONENT_ID"),
                        new ComponentProperty.Identity(
                                rs.getString("GROUPNAME"),
                                rs.getString("PROPERTYNAME"),
                                rs.getString("PROPERTYVALUE"))))
                .list();
    }

    void createComponentProperties(Collection<ComponentProperty> properties) throws InterruptedException {
        inBatches(properties, batch -> {
            handle.createUpdate(/* language=SQL */ """
                INSERT INTO "COMPONENT_PROPERTY" (
                  "UUID"
                , "COMPONENT_ID"
                , "GROUPNAME"
                , "PROPERTYNAME"
                , "PROPERTYVALUE"
                , "PROPERTYTYPE"
                , "DESCRIPTION"
                )
                SELECT GEN_RANDOM_UUID()
                     , t.*
                  FROM UNNEST(:componentIds, :groups, :names, :values, :types, :descriptions) AS t
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#createComponentProperties".formatted(getClass().getSimpleName()))
                    .bindArray(
                            "componentIds",
                            Long.class,
                            columnValues(
                                    batch, property -> property.getComponent().getId()))
                    .bindArray("groups", String.class, columnValues(batch, ComponentProperty::getGroupName))
                    .bindArray("names", String.class, columnValues(batch, ComponentProperty::getPropertyName))
                    .bindArray("values", String.class, columnValues(batch, ComponentProperty::getPropertyValue))
                    .bindArray(
                            "types",
                            String.class,
                            columnValues(batch, property -> Objects.toString(property.getPropertyType(), null)))
                    .bindArray("descriptions", String.class, columnValues(batch, ComponentProperty::getDescription))
                    .execute();
        });
    }

    void deleteComponentProperties(Collection<Long> ids) throws InterruptedException {
        inBatches(ids, batch -> {
            handle.createUpdate(/* language=SQL */ """
                DELETE
                  FROM "COMPONENT_PROPERTY"
                 WHERE "ID" = ANY(:ids)
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#deleteComponentProperties".formatted(getClass().getSimpleName()))
                    .bindArray("ids", Long.class, batch)
                    .execute();
        });
    }

    List<ExistingComponentOccurrenceRow> getComponentOccurrences(long projectId) {
        return handle.createQuery(/* language=SQL */ """
            SELECT occ."ID"
                 , occ."COMPONENT_ID"
                 , occ."LOCATION"
                 , occ."LINE"
                 , occ."OFFSET"
                 , occ."SYMBOL"
              FROM "COMPONENT_OCCURRENCE" AS occ
             INNER JOIN "COMPONENT" AS cmp
                ON cmp."ID" = occ."COMPONENT_ID"
             WHERE cmp."PROJECT_ID" = :projectId
            """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#getComponentOccurrences".formatted(getClass().getSimpleName()))
                .bind("projectId", projectId)
                .map((rs, _) -> new ExistingComponentOccurrenceRow(
                        rs.getObject("ID", UUID.class),
                        rs.getLong("COMPONENT_ID"),
                        new ComponentOccurrence.Identity(
                                rs.getString("LOCATION"),
                                rs.getObject("LINE", Integer.class),
                                rs.getObject("OFFSET", Integer.class),
                                rs.getString("SYMBOL"))))
                .list();
    }

    void createComponentOccurrences(Collection<ComponentOccurrence> occurrences) throws InterruptedException {
        inBatches(occurrences, batch -> {
            handle.createUpdate(/* language=SQL */ """
                INSERT INTO "COMPONENT_OCCURRENCE" (
                  "ID"
                , "COMPONENT_ID"
                , "LOCATION"
                , "LINE"
                , "OFFSET"
                , "SYMBOL"
                )
                SELECT *
                  FROM UNNEST(:ids, :componentIds, :locations, :lines, :offsets, :symbols)
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#createComponentOccurrences".formatted(getClass().getSimpleName()))
                    .bindArray("ids", UUID.class, columnValues(batch, _ -> UUIDV7_GENERATOR.generate()))
                    .bindArray(
                            "componentIds",
                            Long.class,
                            columnValues(
                                    batch,
                                    occurrence -> occurrence.getComponent().getId()))
                    .bindArray("locations", String.class, columnValues(batch, ComponentOccurrence::getLocation))
                    .bindArray("lines", Integer.class, columnValues(batch, ComponentOccurrence::getLine))
                    .bindArray("offsets", Integer.class, columnValues(batch, ComponentOccurrence::getOffset))
                    .bindArray("symbols", String.class, columnValues(batch, ComponentOccurrence::getSymbol))
                    .execute();
        });
    }

    void deleteComponentOccurrences(Collection<UUID> ids) throws InterruptedException {
        inBatches(ids, batch -> {
            handle.createUpdate(/* language=SQL */ """
                DELETE
                  FROM "COMPONENT_OCCURRENCE"
                 WHERE "ID" = ANY(:ids)
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#deleteComponentOccurrences".formatted(getClass().getSimpleName()))
                    .bindArray("ids", UUID.class, batch)
                    .execute();
        });
    }

    List<ExistingComponentLicenseRow> getComponentLicenses(long projectId) {
        return handle.createQuery(/* language=SQL */ """
            SELECT cl."ID"
                 , cl."COMPONENT_ID"
                 , cl."LICENSE_ID"
                 , cl."LICENSE"
                 , cl."LICENSE_EXPRESSION"
                 , cl."LICENSE_URL"
                 , cl."ORDINALITY"
                 , cl."ACKNOWLEDGEMENT"
              FROM "COMPONENTLICENSES" AS cl
             INNER JOIN "COMPONENT" AS cmp
                ON cmp."ID" = cl."COMPONENT_ID"
             WHERE cmp."PROJECT_ID" = :projectId
            """)
                .define(
                        ATTRIBUTE_QUERY_NAME,
                        "%s#getComponentLicenses".formatted(getClass().getSimpleName()))
                .bind("projectId", projectId)
                .map((rs, _) -> new ExistingComponentLicenseRow(
                        rs.getLong("ID"),
                        rs.getLong("COMPONENT_ID"),
                        new ComponentLicenseDao.ComponentLicenseRow(
                                rs.getLong("COMPONENT_ID"),
                                rs.getObject("LICENSE_ID", Long.class),
                                rs.getString("LICENSE"),
                                rs.getString("LICENSE_EXPRESSION"),
                                rs.getString("LICENSE_URL"),
                                rs.getLong("ORDINALITY"),
                                rs.getString("ACKNOWLEDGEMENT"))))
                .list();
    }

    void deleteComponentLicenses(Collection<Long> ids) throws InterruptedException {
        inBatches(ids, batch -> {
            handle.createUpdate(/* language=SQL */ """
                DELETE
                  FROM "COMPONENTLICENSES"
                 WHERE "ID" = ANY(:ids)
                """)
                    .define(
                            ATTRIBUTE_QUERY_NAME,
                            "%s#deleteComponentLicenses".formatted(getClass().getSimpleName()))
                    .bindArray("ids", Long.class, batch)
                    .execute();
        });
    }

    void createComponentLicenses(Collection<ComponentLicenseDao.ComponentLicenseRow> rows) throws InterruptedException {
        final var componentLicenseDao = handle.attach(ComponentLicenseDao.class);
        inBatches(rows, componentLicenseDao::createAll);
    }

    private static void bindComponentColumns(Update update, List<Component> components) {
        update.bindArray(
                        "authors",
                        String.class,
                        columnValues(components, c -> CONTACTS_CONVERTER.convertToDatastore(c.getAuthors())))
                .bindArray("publishers", String.class, columnValues(components, Component::getPublisher))
                .bindArray(
                        "suppliers",
                        String.class,
                        columnValues(components, c -> ENTITY_CONVERTER.convertToDatastore(c.getSupplier())))
                .bindArray(
                        "classifiers",
                        String.class,
                        columnValues(components, c -> Objects.toString(c.getClassifier(), null)))
                .bindArray("groups", String.class, columnValues(components, Component::getGroup))
                .bindArray("names", String.class, columnValues(components, Component::getName))
                .bindArray("versions", String.class, columnValues(components, Component::getVersion))
                .bindArray("descriptions", String.class, columnValues(components, Component::getDescription))
                .bindArray("copyrights", String.class, columnValues(components, Component::getCopyright))
                .bindArray("cpes", String.class, columnValues(components, Component::getCpe))
                .bindArray("purls", String.class, columnValues(components, Component::getPurlAsString))
                .bindArray(
                        "purlCoordinates",
                        String.class,
                        columnValues(components, c -> Objects.toString(c.getPurlCoordinates(), null)))
                .bindArray("swidTagIds", String.class, columnValues(components, Component::getSwidTagId))
                .bindArray("md5s", String.class, columnValues(components, Component::getMd5))
                .bindArray("sha1s", String.class, columnValues(components, Component::getSha1))
                .bindArray("sha256s", String.class, columnValues(components, Component::getSha256))
                .bindArray("sha384s", String.class, columnValues(components, Component::getSha384))
                .bindArray("sha512s", String.class, columnValues(components, Component::getSha512))
                .bindArray("sha3_256s", String.class, columnValues(components, Component::getSha3_256))
                .bindArray("sha3_384s", String.class, columnValues(components, Component::getSha3_384))
                .bindArray("sha3_512s", String.class, columnValues(components, Component::getSha3_512))
                .bindArray("blake2b_256s", String.class, columnValues(components, Component::getBlake2b_256))
                .bindArray("blake2b_384s", String.class, columnValues(components, Component::getBlake2b_384))
                .bindArray("blake2b_512s", String.class, columnValues(components, Component::getBlake2b_512))
                .bindArray("blake3s", String.class, columnValues(components, Component::getBlake3))
                .bindArray("streebog_256s", String.class, columnValues(components, Component::getStreebog_256))
                .bindArray("streebog_512s", String.class, columnValues(components, Component::getStreebog_512))
                .bindArray(
                        "licenseIds",
                        Long.class,
                        columnValues(
                                components,
                                c -> c.getResolvedLicense() != null
                                        ? c.getResolvedLicense().getId()
                                        : null))
                .bindArray("licenses", String.class, columnValues(components, Component::getLicense))
                .bindArray("licenseUrls", String.class, columnValues(components, Component::getLicenseUrl))
                .bindArray(
                        "licenseExpressions", String.class, columnValues(components, Component::getLicenseExpression))
                .bindArray("internals", Boolean.class, columnValues(components, Component::isInternal))
                .bindArray(
                        "externalReferences",
                        byte[].class,
                        columnValues(components, c -> serialize(c.getExternalReferences())))
                .bindArray("scopes", String.class, columnValues(components, c -> Objects.toString(c.getScope(), null)))
                .bindArray(
                        "directDependencies", String.class, columnValues(components, Component::getDirectDependencies));
    }

    private static void bindServiceColumns(Update update, List<ServiceComponent> services) {
        update.bindArray("groups", String.class, columnValues(services, ServiceComponent::getGroup))
                .bindArray("names", String.class, columnValues(services, ServiceComponent::getName))
                .bindArray("versions", String.class, columnValues(services, ServiceComponent::getVersion))
                .bindArray("descriptions", String.class, columnValues(services, ServiceComponent::getDescription))
                .bindArray("authenticated", Boolean.class, columnValues(services, ServiceComponent::getAuthenticated))
                .bindArray(
                        "crossesTrustBoundary",
                        Boolean.class,
                        columnValues(services, ServiceComponent::getCrossesTrustBoundary))
                .bindArray(
                        "externalReferences",
                        byte[].class,
                        columnValues(services, s -> serialize(s.getExternalReferences())))
                .bindArray("providers", byte[].class, columnValues(services, s -> serialize(s.getProvider())))
                .bindArray("data", byte[].class, columnValues(services, s -> serialize(s.getData())))
                .bindArray("endpoints", byte[].class, columnValues(services, s -> serialize(s.getEndpoints())));
    }

    private static <T> void inBatches(Collection<T> rows, Consumer<List<T>> consumer) throws InterruptedException {
        for (final List<T> batch : (Iterable<List<T>>)
                () -> rows.stream().gather(Gatherers.windowFixed(BATCH_SIZE)).iterator()) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all rows could be written");
            }

            consumer.accept(batch);
        }
    }

    private static byte @Nullable [] serialize(@Nullable List<? extends Serializable> list) {
        return list != null ? SerializationUtils.serialize(new ArrayList<>(list)) : null;
    }

    private static byte @Nullable [] serialize(@Nullable Serializable value) {
        return value != null ? SerializationUtils.serialize(value) : null;
    }
}
