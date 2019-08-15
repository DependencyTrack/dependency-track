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
package org.dependencytrack.parser.nvd;

import alpine.event.framework.Event;
import alpine.logging.Logger;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Cpe;
import org.dependencytrack.model.CpeReference;
import org.dependencytrack.persistence.QueryManager;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses official CPE Dictionary v2.3 XML datafiles.
 * https://nvd.nist.gov/products/cpe
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class CpeDictionaryParser {

    private static final Logger LOGGER = Logger.getLogger(CpeDictionaryParser.class);

    public void parse(final File file) {
        if (!file.getName().endsWith(".xml")) {
            return;
        }
        LOGGER.info("Parsing " + file.getName());
        LOGGER.info("This may take several minutes");
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        try (InputStream in = Files.newInputStream(file.toPath())) {
            final XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(in);
            Cpe cpe = new Cpe();
            List<CpeReference> cpeReferences = new ArrayList<>();
            while (xmlEventReader.hasNext()) {
                XMLEvent xmlEvent = xmlEventReader.nextEvent();
                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    if (startElement.getName().getLocalPart().equals("cpe-item")) {
                        cpe = new Cpe();
                        cpeReferences = new ArrayList<>();
                        final Attribute attrName = startElement.getAttributeByName(new QName("name"));
                        if(attrName != null) {
                            cpe.setCpe22(attrName.getValue());
                        }
                    } else if (startElement.getName().getLocalPart().equals("title")) {
                        xmlEvent = xmlEventReader.nextEvent();
                        cpe.setTitle(xmlEvent.asCharacters().getData());
                    } else if (startElement.getName().getLocalPart().equals("reference")) {
                        xmlEvent = xmlEventReader.nextEvent();
                        final CpeReference reference = new CpeReference();
                        final Attribute attrHref = startElement.getAttributeByName(new QName("href"));
                        if (attrHref != null) {
                            reference.setHref(attrHref.getValue());
                        }
                        reference.setName(xmlEvent.asCharacters().getData());
                        cpeReferences.add(reference);
                    } else if (startElement.getName().getLocalPart().equals("cpe23-item")) {
                        final Attribute attrName = startElement.getAttributeByName(new QName("name"));
                        if(attrName != null) {
                            cpe.setCpe23(attrName.getValue());
                            try {
                                ModelConverter.convertCpe23Uri(cpe, cpe.getCpe23());
                            } catch (CpeEncodingException | CpeParsingException e) {
                                LOGGER.error("An error occurred while parsing: " + cpe.getCpe23(), e);
                            }
                        }
                    }
                }
                if (xmlEvent.isEndElement()) {
                    EndElement endElement = xmlEvent.asEndElement();
                    if(endElement.getName().getLocalPart().equals("cpe-item")) {
                        try (QueryManager qm = new QueryManager()) {
                            if (cpe != null) {
                                cpe = qm.synchronizeCpe(cpe, false);
                            }
                            for (CpeReference reference: cpeReferences) {
                                reference.setCpe(cpe);
                                qm.persist(reference);
                            }
                        }
                    }
                }
            }
        } catch (IOException | XMLStreamException e) {
            LOGGER.error("An error occurred processing the CPE dictionary", e);
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Cpe.class));
    }
}
