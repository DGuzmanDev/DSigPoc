package cr.poc.firmador.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class OfficeDocumentDebugger {
    private static final Logger LOG = LogManager.getLogger(MethodHandles.lookup().lookupClass());

    /**
     * Extracts and logs the contents of an Office document (docx, xlsx, etc.) for debugging purposes.
     * 
     * @param officeFile The Office document file to analyze
     * @param contextLabel A label to identify the context of the extraction (e.g., "original", "signed")
     * @return The path to the directory containing the extracted contents, or null if extraction failed
     */
    public static String extractAndLogContents(File officeFile, String contextLabel) {
        try {
            // Create debug directory
            Path debugDir = Files.createDirectory(Path.of("debug_office_" + contextLabel + "_" + System.currentTimeMillis()));
            LOG.info("Extracting Office document contents to: {}", debugDir);

            try (ZipFile zip = new ZipFile(officeFile)) {
                Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String entryName = entry.getName();
                    Path targetPath = debugDir.resolve(entryName);

                    // Create parent directories if needed
                    Files.createDirectories(targetPath.getParent());

                    // Save the file content
                    if (!entry.isDirectory()) {
                        try (InputStream is = zip.getInputStream(entry)) {
                            Files.copy(is, targetPath);
                            
                            // For XML files, log their content for easier debugging
                            if (entryName.endsWith(".xml") || entryName.endsWith(".rels")) {
                                String content = new String(Files.readAllBytes(targetPath), "UTF-8");
                                LOG.info("Content of {}: \n{}", entryName, content);
                            }
                        }
                    }
                }
            }
            
            return debugDir.toString();
        } catch (IOException e) {
            LOG.error("Error extracting Office document contents", e);
            return null;
        }
    }
}