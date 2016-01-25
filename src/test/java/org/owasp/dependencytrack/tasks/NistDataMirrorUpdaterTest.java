package org.owasp.dependencytrack.tasks;

import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Created by Jason Wraxall on 22/12/15.
 */
public class NistDataMirrorUpdaterTest {

    @Test
    public void testIsValidNistFileForValidFiles() throws Exception {
        String[] validFilenames = {
                "nvdcve-Modified.xml.gz",
                "nvdcve-2.0-Modified.xml.gz",
                "nvdcve-2005.xml.gz",
                "nvdcve-2.0-2005.xml.gz"
        };


        for (String validFilename : validFilenames) {
            assertThat("Is valid:"+validFilename,NistDataMirrorUpdater.isValidNistFile(validFilename), is(true));
        }

    }

    @Test
    public void testIsValidNistFileForInvalidFiles() throws Exception {
        String[] invalidFilenames = {
                "nvdcves-Modified.xml.gz",
                "nvdcve-2.0-Modified.xml.gaz",
                "nvdcve-2005d.xml.gz",
                "nvdcve-2.0-20078.xml.gz"
        };

        for (String invalidFilename : invalidFilenames) {
            assertThat("Is invalid:"+invalidFilename,NistDataMirrorUpdater.isValidNistFile(invalidFilename), is(false));
        }

    }
}