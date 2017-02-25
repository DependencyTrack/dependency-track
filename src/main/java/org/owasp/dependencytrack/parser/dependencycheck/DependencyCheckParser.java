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

public class DependencyCheckParser {

    public Analysis parse(File file) throws ParseException {
        return parse(new StreamSource(file.getAbsolutePath()));
    }

    public Analysis parse(byte[] scanData) throws ParseException {
        return parse(new StreamSource(new ByteArrayInputStream(scanData)));
    }

    private Analysis parse(StreamSource streamSource) throws ParseException {
        try {
            // Parse the native threat model
            JAXBContext jaxbContext = JAXBContext.newInstance(Analysis.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();

            // Prevent XML External Entity Injection
            XMLInputFactory xif = XMLInputFactory.newFactory();
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xif.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, false);
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            XMLStreamReader xsr = xif.createXMLStreamReader(streamSource);

            return (Analysis)unmarshaller.unmarshal(xsr);

        } catch (JAXBException | XMLStreamException e) {
            throw new ParseException(e);
        }
    }
}
