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
package org.dependencytrack.vulndatasource.jvn;

import org.jspecify.annotations.Nullable;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stax.StAXSource;
import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Iterator;
import java.util.NoSuchElementException;

import static java.util.Objects.requireNonNull;

/**
 * Streams the {@code <Vulinfo>} entries of a VULDEF detail feed, materializing one
 * {@link JvnAdvisory} at a time to keep the memory footprint independent of the feed size.
 * <p>
 * A StAX cursor scans for {@code Vulinfo} start elements; each matched subtree — a few KB —
 * is copied into a small DOM fragment and handed to {@link JvnDetailParser#parseVulinfo(Element)},
 * so the per-field extraction logic is shared with no whole-document DOM ever being built.
 *
 * @since 5.1.0
 */
final class JvnAdvisorySource implements Iterator<JvnAdvisory>, Closeable {

    private final InputStream inputStream;
    private final XMLStreamReader xmlReader;
    private final Transformer transformer;
    private @Nullable JvnAdvisory nextAdvisory;

    JvnAdvisorySource(final InputStream inputStream) throws IOException {
        this.inputStream = inputStream;
        try {
            final XMLInputFactory inputFactory = XMLInputFactory.newInstance();
            inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            inputFactory.setProperty(XMLInputFactory.IS_COALESCING, true);
            this.xmlReader = inputFactory.createXMLStreamReader(inputStream);

            final TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            this.transformer = transformerFactory.newTransformer();
        } catch (XMLStreamException | TransformerException | RuntimeException e) {
            try {
                inputStream.close();
            } catch (IOException closeException) {
                e.addSuppressed(closeException);
            }
            throw new IOException("Failed to open JVN detail feed", e);
        }
    }

    /**
     * Opens a downloaded feed file for streaming; the file is deleted once the source is closed.
     */
    static JvnAdvisorySource open(final Path feedFilePath) throws IOException {
        return new JvnAdvisorySource(new BufferedInputStream(
                Files.newInputStream(feedFilePath, StandardOpenOption.DELETE_ON_CLOSE)));
    }

    @Override
    public boolean hasNext() {
        if (nextAdvisory == null) {
            nextAdvisory = advance();
        }
        return nextAdvisory != null;
    }

    @Override
    public JvnAdvisory next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        final JvnAdvisory advisory = requireNonNull(nextAdvisory);
        nextAdvisory = null;
        return advisory;
    }

    @Override
    public void close() throws IOException {
        try {
            xmlReader.close();
        } catch (XMLStreamException e) {
            throw new IOException("Failed to close JVN detail feed reader", e);
        } finally {
            inputStream.close();
        }
    }

    private @Nullable JvnAdvisory advance() {
        try {
            while (true) {
                final int event = xmlReader.getEventType();
                if (event == XMLStreamConstants.START_ELEMENT
                        && "Vulinfo".equals(xmlReader.getLocalName())) {
                    // The identity transform consumes the reader through the matching end element
                    // plus one further event, so the loop must re-examine the current event rather
                    // than advancing — an immediately following <Vulinfo> would be skipped otherwise.
                    final var domResult = new DOMResult();
                    transformer.transform(new StAXSource(xmlReader), domResult);
                    final Element vulinfo = ((Document) domResult.getNode()).getDocumentElement();
                    final JvnAdvisory advisory = JvnDetailParser.parseVulinfo(vulinfo);
                    if (advisory != null) {
                        return advisory;
                    }
                    continue;
                }
                if (event == XMLStreamConstants.END_DOCUMENT || !xmlReader.hasNext()) {
                    return null;
                }
                xmlReader.next();
            }
        } catch (XMLStreamException | TransformerException e) {
            throw new IllegalArgumentException("Failed to parse JVN detail XML", e);
        }
    }
}
