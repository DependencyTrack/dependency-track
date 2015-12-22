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
package org.owasp.dependencytrack.util;

import org.codehaus.staxmate.SMInputFactory;

import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLInputFactory;

/**
 * XML utilities.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public final class XmlUtil {

    /**
     * Private constructor.
     */
    private XmlUtil() { }

    /**
     * Creates a new instance of a StaxMate InputFactory parser.
     * @return a new StaxMate InputFactory
     * @throws FactoryConfigurationError if the configuration for the parser encounters an exception
     */
    public static SMInputFactory newStaxParser() throws FactoryConfigurationError {
        final XMLInputFactory xmlFactory = XMLInputFactory.newInstance();
        xmlFactory.setProperty(XMLInputFactory.IS_COALESCING, Boolean.TRUE);
        xmlFactory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, Boolean.FALSE);
        xmlFactory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        xmlFactory.setProperty(XMLInputFactory.IS_VALIDATING, Boolean.FALSE);
        return new SMInputFactory(xmlFactory);
    }
}
