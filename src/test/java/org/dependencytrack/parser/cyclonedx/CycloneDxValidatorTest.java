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
package org.dependencytrack.parser.cyclonedx;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

@RunWith(JUnitParamsRunner.class)
public class CycloneDxValidatorTest {

    private CycloneDxValidator validator;

    @Before
    public void setUp() {
        validator = new CycloneDxValidator();
    }

    @Test
    public void testValidateWithEmptyBytes() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("".getBytes()))
                .withMessage("BOM is neither valid JSON nor XML");
    }

    @Test
    public void testValidateWithEmptyJson() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("{}".getBytes()))
                .withMessage("Unable to determine schema version from JSON");
    }

    @Test
    public void testValidateWithEmptyXml() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("<bom></bom>".getBytes()))
                .withMessage("Unable to determine schema version from XML namespaces []");
    }

    @Test
    public void testValidateJsonWithoutSpecVersion() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("""
                        {
                          "components": []
                        }
                        """.getBytes()))
                .withMessage("Unable to determine schema version from JSON");
    }

    @Test
    public void testValidateJsonWithUnsupportedSpecVersion() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("""
                        {
                          "specVersion": "1.1",
                          "components": []
                        }
                        """.getBytes()))
                .withMessage("JSON is not supported for specVersion 1.1");
    }

    @Test
    public void testValidateJsonWithUnknownSpecVersion() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("""
                        {
                          "specVersion": "666",
                          "components": []
                        }
                        """.getBytes()))
                .withMessage("Unrecognized specVersion 666");
    }

    @Test
    public void testValidateXmlWithoutNamespace() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("""
                        <bom>
                          <components/>
                        </bom>
                        """.getBytes()))
                .withMessage("Unable to determine schema version from XML namespaces []");
    }

    @Test
    public void testValidateXmlWithoutNamespace2() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("""
                        <bom xmlns="http://cyclonedx.org/schema/bom/666">
                          <components/>
                        </bom>
                        """.getBytes()))
                .withMessage("Unable to determine schema version from XML namespaces [http://cyclonedx.org/schema/bom/666]");
    }

    @Test
    public void testValidateJsonWithInvalidComponentType() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("""
                        {
                          "bomFormat": "CycloneDX",
                          "specVersion": "1.2",
                          "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                          "version": 1,
                          "components": [
                            {
                              "type": "foo",
                              "name": "acme-library",
                              "version": "1.0.0"
                            }
                          ]
                        }
                        """.getBytes()))
                .withMessage("Schema validation failed")
                .extracting(InvalidBomException::getValidationErrors).asList()
                .containsExactly("""
                        $.components[0].type: does not have a value in the enumeration \
                        [application, framework, library, container, operating-system, device, firmware, file]\
                        """);
    }

    @Test
    public void testValidateXmlWithInvalidComponentType() {
        assertThatExceptionOfType(InvalidBomException.class)
                .isThrownBy(() -> validator.validate("""
                        <?xml version="1.0"?>
                         <bom serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1" xmlns="http://cyclonedx.org/schema/bom/1.2">
                             <components>
                                 <component type="foo">
                                     <name>acme-library</name>
                                     <version>1.0.0</version>
                                 </component>
                             </components>
                         </bom>
                        """.getBytes()))
                .withMessage("Schema validation failed")
                .extracting(InvalidBomException::getValidationErrors).asList()
                .containsExactly(
                        """
                                cvc-enumeration-valid: Value 'foo' is not facet-valid with respect to enumeration \
                                '[application, framework, library, container, operating-system, device, firmware, file]'. \
                                It must be a value from the enumeration.""",
                        """
                                cvc-attribute.3: The value 'foo' of attribute 'type' on element 'component' is not \
                                valid with respect to its type, 'classification'.""");
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/3696
    public void testValidateJsonWithSpecVersionAtTheBottom() {
        assertThatNoException()
                .isThrownBy(() -> validator.validate("""
                        {
                          "metadata": {},
                          "components": [],
                          "bomFormat": "CycloneDX",
                          "specVersion": "1.5"
                        }
                        """.getBytes()));
    }

    @SuppressWarnings("unused")
    private Object[] testValidateWithValidBomParameters() throws Exception {
        final PathMatcher pathMatcherJson = FileSystems.getDefault().getPathMatcher("glob:**/valid-bom-*.json");
        final PathMatcher pathMatcherXml = FileSystems.getDefault().getPathMatcher("glob:**/valid-bom-*.xml");
        final var bomFilePaths = new ArrayList<Path>();

        Files.walkFileTree(Paths.get("./src/test/resources/unit/cyclonedx"), new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(final Path file, final BasicFileAttributes attrs) {
                if (pathMatcherJson.matches(file) || pathMatcherXml.matches(file)) {
                    bomFilePaths.add(file);
                }

                return FileVisitResult.CONTINUE;
            }
        });

        return bomFilePaths.stream().sorted().toArray();
    }

    @Test
    @Parameters(method = "testValidateWithValidBomParameters")
    public void testValidateWithValidBom(final Path bomFilePath) throws Exception {
        final byte[] bomBytes = Files.readAllBytes(bomFilePath);

        assertThatNoException().isThrownBy(() -> validator.validate(bomBytes));
    }

}