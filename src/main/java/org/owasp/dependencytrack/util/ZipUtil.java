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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.io.IOUtils;

/**
 * Zip utilities.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public final class ZipUtil {

    /**
     * Private constructor.
     */
    private ZipUtil() { }

    /**
     * Creates a zip file at the specified path with the contents of the specified directory.
     *
     * @param directoryPath The path of the directory where the archive will be created. eg. c:/temp
     * @param zipPath The full path of the archive to create. eg. c:/temp/archive.zip
     * @throws IOException If anything goes wrong
     */
    public static void createZip(String directoryPath, String zipPath) throws IOException {
        FileOutputStream fOut = null;
        BufferedOutputStream bOut = null;
        ZipArchiveOutputStream tOut = null;

        try {
            fOut = new FileOutputStream(new File(zipPath));
            bOut = new BufferedOutputStream(fOut);
            tOut = new ZipArchiveOutputStream(bOut);
            addFileToZip(tOut, directoryPath, "");
            tOut.finish();
        } finally {
            IOUtils.closeQuietly(tOut);
            IOUtils.closeQuietly(bOut);
            IOUtils.closeQuietly(fOut);
        }
    }

    /**
     * Creates a zip entry for the path specified with a name built from the base passed in and the file/directory
     * name. If the path is a directory, a recursive call is made such that the full directory is added to the zip.
     *
     * @param zOut The zip file's output stream
     * @param path The filesystem path of the file/directory being added
     * @param base The base prefix to for the name of the zip file entry
     *
     * @throws IOException If anything goes wrong
     */
    private static void addFileToZip(ZipArchiveOutputStream zOut, String path, String base) throws IOException {
        final File f = new File(path);
        final String entryName = base + f.getName();
        final ZipArchiveEntry zipEntry = new ZipArchiveEntry(f, entryName);

        zOut.putArchiveEntry(zipEntry);

        if (f.isFile()) {
            FileInputStream fInputStream = null;
            try {
                fInputStream = new FileInputStream(f);
                IOUtils.copy(fInputStream, zOut);
                zOut.closeArchiveEntry();
            } finally {
                IOUtils.closeQuietly(fInputStream);
            }

        } else {
            zOut.closeArchiveEntry();
            final File[] children = f.listFiles();

            if (children != null) {
                for (File child : children) {
                    addFileToZip(zOut, child.getAbsolutePath(), entryName + "/");
                }
            }
        }
    }
}
