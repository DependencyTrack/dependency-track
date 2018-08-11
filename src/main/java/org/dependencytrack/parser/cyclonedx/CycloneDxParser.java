/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

package org.dependencytrack.parser.cyclonedx;

import alpine.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.exception.ParseException;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.parser.cyclonedx.model.Bom;
import org.dependencytrack.parser.cyclonedx.model.Hash;
import org.dependencytrack.persistence.QueryManager;
import org.xml.sax.SAXException;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.UnmarshalException;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * CycloneDX Bill-of-Material parser.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class CycloneDxParser {

    private static final Logger LOGGER = Logger.getLogger(CycloneDxParser.class);

    private QueryManager qm;

    public CycloneDxParser(QueryManager qm) {
        this.qm = qm;
    }

    /**
     * Parses a CycloneDX BOM.
     *
     * @param file the BOM
     * @return an Bom object
     * @throws ParseException when errors are encountered
     */
    public Bom parse(File file) throws ParseException {
        return parse(new StreamSource(file.getAbsolutePath()));
    }

    /**
     * Parses a CycloneDX BOM.
     *
     * @param bomBytes the BOM
     * @return an Bom object
     * @throws ParseException when errors are encountered
     */
    public Bom parse(byte[] bomBytes) throws ParseException {
        return parse(new StreamSource(new ByteArrayInputStream(bomBytes)));
    }

    /**
     * Parses a CycloneDX BOM.
     *
     * @param streamSource the BOM
     * @return an Bom object
     * @throws ParseException when errors are encountered
     */
    private Bom parse(StreamSource streamSource) throws ParseException {
        try {
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

            // Use local copies of schemas rather than resolving from the net. It's faster, and less prone to errors.
            Source[] schemaFiles = {
                    new StreamSource(getClass().getClassLoader().getResourceAsStream("schema/cyclonedx/spdx.xsd")),
                    new StreamSource(getClass().getClassLoader().getResourceAsStream("schema/cyclonedx/bom-1.0.xsd"))
            };
            Schema schema = schemaFactory.newSchema(schemaFiles);

            // Parse the native bom
            final JAXBContext jaxbContext = JAXBContext.newInstance(Bom.class);
            final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            unmarshaller.setSchema(schema);

            // Prevent XML External Entity Injection
            final XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            final XMLStreamReader xsr = xif.createXMLStreamReader(streamSource);

            return (Bom) unmarshaller.unmarshal(xsr);
        } catch (UnmarshalException e) {
            LOGGER.error("Invalid CycloneDX BOM. Unable to parse.", e);
            throw new ParseException(e);
        } catch (JAXBException | XMLStreamException | SAXException e) {
            LOGGER.error("An error occurred parsing CycloneDX BOM", e);
            throw new ParseException(e);
        }
    }

    /**
     * Converts a parsed Bom to a native list of Dependency-Track component object
     * @param bom the Bom to convert
     * @return a List of Component object
     */
    public List<Component> convert(Bom bom) {
        final List<Component> components = new ArrayList<>();
        for (int i = 0; i < bom.getComponents().size(); i++) {
            components.add(convert(bom.getComponents().get(i)));
        }
        return components;
    }

    private Component convert(org.dependencytrack.parser.cyclonedx.model.Component cycloneDxComponent) {
        final Component component = new Component();
        component.setGroup(StringUtils.trimToNull(cycloneDxComponent.getGroup()));
        component.setName(StringUtils.trimToNull(cycloneDxComponent.getName()));
        component.setVersion(StringUtils.trimToNull(cycloneDxComponent.getVersion()));
        component.setDescription(StringUtils.trimToNull(cycloneDxComponent.getDescription()));
        component.setCopyright(StringUtils.trimToNull(cycloneDxComponent.getCopyright()));
        component.setCpe(StringUtils.trimToNull(cycloneDxComponent.getCpe()));

        try {
            component.setPurl(new PackageURL(cycloneDxComponent.getPurl()));
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Unable to parse PackageURL: " + cycloneDxComponent.getPurl());
        }

        final String type = StringUtils.trimToNull(cycloneDxComponent.getType());
        if ("application".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.APPLICATION);
        } else if ("framework".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.FRAMEWORK);
        } else if ("library".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.LIBRARY);
        } else if ("operating-system".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.OPERATING_SYSTEM);
        } else if ("device".toUpperCase().equals(type.toUpperCase())) {
            component.setClassifier(Classifier.DEVICE);
        }

        for (Hash hash : cycloneDxComponent.getHashes()) {
            if ("MD5".equalsIgnoreCase(hash.getAlgorithm())) {
                component.setMd5(StringUtils.trimToNull(hash.getHash()));
            } else if ("SHA-1".equalsIgnoreCase(hash.getAlgorithm())) {
                component.setSha1(StringUtils.trimToNull(hash.getHash()));
            } else if ("SHA-256".equalsIgnoreCase(hash.getAlgorithm())) {
                component.setSha256(StringUtils.trimToNull(hash.getHash()));
            } else if ("SHA-512".equalsIgnoreCase(hash.getAlgorithm())) {
                component.setSha512(StringUtils.trimToNull(hash.getHash()));
            } else if ("SHA3-256".equalsIgnoreCase(hash.getAlgorithm())) {
                component.setSha3_256(StringUtils.trimToNull(hash.getHash()));
            } else if ("SHA3-512".equalsIgnoreCase(hash.getAlgorithm())) {
                component.setSha3_512(StringUtils.trimToNull(hash.getHash()));
            }
        }

        for (org.dependencytrack.parser.cyclonedx.model.License cycloneLicense: cycloneDxComponent.getLicenses()) {
            if (StringUtils.isNotBlank(cycloneLicense.getId())) {
                License license = qm.getLicense(StringUtils.trimToNull(cycloneLicense.getId()));
                if (license != null) {
                    component.setResolvedLicense(license);
                }
            }
            component.setLicense(StringUtils.trimToNull(cycloneLicense.getName()));
        }

        final Collection<Component> components = new ArrayList<>();
        for (int i = 0; i < cycloneDxComponent.getComponents().size(); i++) {
            components.add(convert(cycloneDxComponent.getComponents().get(i)));
        }
        if (components.size() > 0) {
            component.setChildren(components);
        }

        return component;
    }

}