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
package org.owasp.dependencytrack.parser.dependencycheck;

import org.owasp.dependencytrack.exception.ParseException;
import org.owasp.dependencytrack.parser.dependencycheck.model.Analysis;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.File;

/**
 * Dependency-Check XML report parser.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class DependencyCheckParser {

    /**
     * Parses a Dependency-Check report.
     * @param file the XML report
     * @return an Analysis object
     * @throws ParseException when errors are encountered
     */
    public Analysis parse(File file) throws ParseException {
        return parse(new StreamSource(file.getAbsolutePath()));
    }

    /**
     * Parses a Dependency-Check report.
     * @param scanData the XML report
     * @return an Analysis object
     * @throws ParseException when errors are encountered
     */
    public Analysis parse(byte[] scanData) throws ParseException {
        return parse(new StreamSource(new ByteArrayInputStream(scanData)));
    }

    /**
     * Parses a Dependency-Check report.
     * @param streamSource the XML report
     * @return an Analysis object
     * @throws ParseException when errors are encountered
     */
    private Analysis parse(StreamSource streamSource) throws ParseException {
        try {
            // Parse the native threat model
            final JAXBContext jaxbContext = JAXBContext.newInstance(Analysis.class);
            final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();

            // Prevent XML External Entity Injection
            final XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            final XMLStreamReader xsr = xif.createXMLStreamReader(streamSource);

            return (Analysis) unmarshaller.unmarshal(xsr);

        } catch (JAXBException | XMLStreamException e) {
            throw new ParseException(e);
        }
    }
}
