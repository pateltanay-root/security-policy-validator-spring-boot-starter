package com.research.securitypolicy.upload;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ProjectExtractor {

    public Path extract(
            InputStream zipInputStream)
            throws IOException {

        if (zipInputStream == null) {
            throw new IllegalArgumentException(
                    "ZIP input stream must not be null"
            );
        }

        Path tempDirectory =
                Files.createTempDirectory(
                        "security-policy-analysis-"
                );

        try (ZipInputStream zip =
                     new ZipInputStream(zipInputStream)) {

            ZipEntry entry;

            while ((entry = zip.getNextEntry()) != null) {

                Path target =
                        tempDirectory
                                .resolve(entry.getName())
                                .normalize();

                /*
                 * Prevent ZIP Slip attacks.
                 */
                if (!target.startsWith(tempDirectory)) {
                    throw new IOException(
                            "Unsafe ZIP entry: "
                                    + entry.getName()
                    );
                }

                if (entry.isDirectory()) {

                    Files.createDirectories(target);

                } else {

                    Path parent =
                            target.getParent();

                    if (parent != null) {
                        Files.createDirectories(parent);
                    }

                    Files.copy(
                            zip,
                            target,
                            StandardCopyOption.REPLACE_EXISTING
                    );
                }

                zip.closeEntry();
            }
        }

        return tempDirectory;
    }
}