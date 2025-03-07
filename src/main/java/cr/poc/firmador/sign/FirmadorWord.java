package cr.poc.firmador.sign;

import cr.poc.firmador.card.CardSignInfo;
import cr.poc.firmador.settings.Settings;
import cr.poc.firmador.settings.SettingsManager;
import cr.poc.firmador.utils.OfficeDocumentDebugger;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.signature.XAdESService;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

@NoArgsConstructor
public class FirmadorWord extends CRSigner implements AutoCloseable {
    final Logger LOG = LogManager.getLogger(MethodHandles.lookup().lookupClass());
    XAdESSignatureParameters parameters;
    private Settings settings = SettingsManager.getInstance().getAndCreateSettings();

    private static final String WORD_MAIN_DOCUMENT = "word/document.xml";
    private static final String WORD_RELS_FILE = "word/_rels/document.xml.rels";
    private static final String SIGNATURES_DIR = "_xmlsignatures/";
    private static final String SIGNATURE_FILE = "_xmlsignatures/sig1.xml";
    private static final String SIGNATURE_ORIGIN = "_xmlsignatures/origin.sigs";
    private static final String ORIGIN_RELS_FILE = "_xmlsignatures/_rels/origin.sigs.rels";
    private static final String ROOT_RELS_FILE = "_rels/.rels";
    private static final String CONTENT_TYPES_FILE = "[Content_Types].xml";
    // Removed SIG_RELS_FILE constant

    private Path tempDir;
    private File originalDocx;
    private File signedDocx;

    public DSSDocument sign(DSSDocument wordDocument, CardSignInfo card) {
        try {
            tempDir = Files.createTempDirectory("word_signing_");
            originalDocx = new File(tempDir.toFile(), "original.docx");
            wordDocument.save(originalDocx.getPath());

            // Debug: Extract original document contents
//            OfficeDocumentDebugger.extractAndLogContents(originalDocx, "original");

            // Extract and sign document.xml
            byte[] mainDocumentXml = extractFileFromZip(originalDocx, WORD_MAIN_DOCUMENT);
            if (mainDocumentXml == null) {
                LOG.error("Could not find main document.xml in Word file");
                return null;
            }

            // Create signature
            DSSDocument xmlDocument = new InMemoryDocument(mainDocumentXml);
            DSSDocument signedXml = signXmlDocument(xmlDocument, card);

            if (signedXml == null) {
                LOG.error("Failed to sign XML document");
                return null;
            }

            // Create new signed docx
            signedDocx = new File(tempDir.toFile(), "signed.docx");
            createSignedDocx(originalDocx, signedDocx, signedXml);

            // Debug: Extract signed document contents
            OfficeDocumentDebugger.extractAndLogContents(signedDocx, "signed");

            return new FileDocument(signedDocx);
        } catch (Exception e) {
            LOG.error("Error during Word document signing", e);
            cleanup();
            return null;
        }
    }

    private byte[] extractFileFromZip(File zipFile, String fileName) throws IOException {
        try (ZipFile zip = new ZipFile(zipFile)) {
            ZipEntry entry = zip.getEntry(fileName);
            if (entry == null) {
                return null;
            }

            try (InputStream is = zip.getInputStream(entry)) {
                return is.readAllBytes();
            }
        }
    }

    private DSSDocument signXmlDocument(DSSDocument xmlDocument, CardSignInfo card) {
        try {
            CertificateVerifier verifier = this.getCertificateVerifier();
            XAdESService service = new XAdESService(verifier);

            // Configure TSP source
            OnlineTSPSource onlineTSPSource = new OnlineTSPSource("http://tsa.sinpe.fi.cr/tsaHttp/");
            service.setTspSource(onlineTSPSource);

            // Initialize signature parameters
            this.parameters = new XAdESSignatureParameters();
            this.parameters.setSignatureLevel(this.settings.getXAdESLevel());
            this.parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
            this.parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // Create reference to the main document
            DSSReference reference = new DSSReference();
            reference.setId("r-" + this.parameters.getDeterministicId());
            reference.setUri("../document.xml");
            reference.setContents(xmlDocument);
            reference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
            this.parameters.setReferences(Arrays.asList(reference));

            // Get signing certificate
            var token = this.getSignatureConnection(card);
            var privateKey = this.getPrivateKey(token);
            var certificate = privateKey.getCertificate();

            this.parameters.setSigningCertificate(certificate);
            this.parameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA256);
            this.parameters.bLevel().setSigningDate(new Date());

            // Sign the document
            var dataToSign = service.getDataToSign(xmlDocument, this.parameters);
            var signatureValue = token.sign(dataToSign, this.parameters.getDigestAlgorithm(), privateKey);
            return service.signDocument(xmlDocument, this.parameters, signatureValue);

        } catch (Exception e) {
            LOG.error("Error signing XML document", e);
            return null;
        }
    }

    private void createSignedDocx(File sourceDocx, File targetDocx, DSSDocument signedXml) throws IOException {
        // Ensure parent directory exists
        File parentDir = targetDocx.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        try (ZipFile sourceZip = new ZipFile(sourceDocx);
             ZipOutputStream targetZip = new ZipOutputStream(new FileOutputStream(targetDocx))) {

            // Copy all existing files except those we'll replace
            copyExistingFiles(sourceZip, targetZip);

            // Add signature directories under word/
            addDirectoryEntry(targetZip, SIGNATURES_DIR);
            addDirectoryEntry(targetZip, SIGNATURES_DIR + "_rels/");

            // Add empty origin.sigs file under word/_xmlsignatures
            addEntry(targetZip, SIGNATURE_ORIGIN, new ByteArrayInputStream(new byte[0]));

            // Add the signature file
            addEntry(targetZip, SIGNATURE_FILE, signedXml.openStream());

            // Add or update relationships and content types
            updateRelationships(targetZip, sourceZip);
            updateContentTypes(targetZip, sourceZip);
        }
    }

    private void copyExistingFiles(ZipFile source, ZipOutputStream target) throws IOException {
        Enumeration<? extends ZipEntry> entries = source.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String entryName = entry.getName();

            // Skip files we'll replace
            if (entryName.equals(SIGNATURE_FILE) ||
                    entryName.equals(ROOT_RELS_FILE) ||
                    entryName.equals(ORIGIN_RELS_FILE) ||
                    entryName.equals(CONTENT_TYPES_FILE) ||
                    entryName.equals(WORD_RELS_FILE)) {
                continue;
            }

            // Copy all other files as-is
            ZipEntry newEntry = new ZipEntry(entryName);
            target.putNextEntry(newEntry);
            try (InputStream is = source.getInputStream(entry)) {
                is.transferTo(target);
            }
            target.closeEntry();
        }
    }

    private void addDirectoryEntry(ZipOutputStream zip, String dirName) throws IOException {
        ZipEntry entry = new ZipEntry(dirName);
        zip.putNextEntry(entry);
        zip.closeEntry();
    }

    private void addEntry(ZipOutputStream zip, String name, InputStream content) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        zip.putNextEntry(entry);
        content.transferTo(zip);
        zip.closeEntry();
    }

    private void updateRelationships(ZipOutputStream zip, ZipFile sourceZip) throws IOException {
        // Add origin.sigs.rels that points to the signature
        String signatureRels = createSignatureRels();
        //Este es el que va dentro de _xmlsignatures
        addEntry(zip, ORIGIN_RELS_FILE, new ByteArrayInputStream(signatureRels.getBytes()));

        // Update root relationships to point to origin.sigs
        updateRootRelationships(zip, sourceZip);

        // Update document.xml.rels WITHOUT the signature reference
        String documentRels = createOrUpdateDocumentRels(sourceZip);
        addEntry(zip, WORD_RELS_FILE, new ByteArrayInputStream(documentRels.getBytes()));
    }

    private String createOrUpdateDocumentRels(ZipFile sourceZip) throws IOException {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
        xml.append("<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n");

        // Copy existing relationships
        ZipEntry relsEntry = sourceZip.getEntry(WORD_RELS_FILE);
        if (relsEntry != null) {
            try (InputStream is = sourceZip.getInputStream(relsEntry)) {
                String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                // Extract only non-signature relationships
                Pattern pattern = Pattern.compile("<Relationship\\s+[^>]+>");
                Matcher matcher = pattern.matcher(content);
                while (matcher.find()) {
                    String relationship = matcher.group(0);
                    // Skip any existing signature relationships and nested Relationships tags
                    if (!relationship.contains("digital-signature") && !relationship.contains("<Relationships")) {
                        xml.append("  ").append(relationship).append("\n");
                    }
                }
            }
        }

        xml.append("</Relationships>");
        return xml.toString();
    }

    //Este es el que va dentro de _xmlsignatures
    private String createSignatureRels() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n" +
                "  <Relationship Id=\"rId1\" " +
                "Type=\"http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature\" " +
                "Target=\"sig1.xml\"/>\n" +  // Removed leading slash as it's relative to origin.sigs
                "</Relationships>";
    }

    private void updateContentTypes(ZipOutputStream zip, ZipFile sourceZip) throws IOException {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        xml.append("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n");

        // Add required content types
        xml.append("  <Default Extension=\"rels\" ")
                .append("ContentType=\"application/vnd.openxmlformats-package.relationships+xml\" />\n");
        xml.append("  <Default Extension=\"xml\" ")
                .append("ContentType=\"application/xml\" />\n");
        xml.append("  <Default Extension=\"sigs\" ")
                .append("ContentType=\"application/vnd.openxmlformats-package.digital-signature-origin\" />\n");

        // Add signature content type with correct root path
        xml.append("  <Override PartName=\"/_xmlsignatures/sig1.xml\" ")
                .append("ContentType=\"application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml\" />\n");

        // Copy existing content types from source
        ZipEntry contentTypesEntry = sourceZip.getEntry(CONTENT_TYPES_FILE);
        if (contentTypesEntry != null) {
            try (InputStream is = sourceZip.getInputStream(contentTypesEntry)) {
                String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                // Extract existing overrides, excluding signature-related ones
                Pattern pattern = Pattern.compile("<Override PartName=\"([^\"]+)\"[^>]+>");
                Matcher matcher = pattern.matcher(content);
                while (matcher.find()) {
                    String partName = matcher.group(1);
                    if (!partName.contains("_xmlsignatures")) {
                        xml.append("  ").append(matcher.group(0)).append("\n");
                    }
                }
            }
        }

        xml.append("</Types>");
        addEntry(zip, CONTENT_TYPES_FILE, new ByteArrayInputStream(xml.toString().getBytes()));
    }

    //este es el root .rels que va en _rels del root
    private void updateRootRelationships(ZipOutputStream zip, ZipFile sourceZip) throws IOException {
        try {
            updateRootRelationshipsDom(zip, sourceZip);
        } catch (Exception e) {
            LOG.warn("DOM-based relationship update failed, falling back to string-based method", e);
            updateRootRelationshipsLegacy(zip, sourceZip);
        }
    }

    private void updateRootRelationshipsDom(ZipOutputStream zip, ZipFile sourceZip) throws IOException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc;
            
            ZipEntry relsEntry = sourceZip.getEntry(ROOT_RELS_FILE);
            if (relsEntry != null) {
                // Parse existing .rels file
                try (InputStream is = sourceZip.getInputStream(relsEntry)) {
                    doc = db.parse(is);
                }
            } else {
                // Create new document if .rels doesn't exist
                doc = db.newDocument();
                Element relationships = doc.createElement("Relationships");
                relationships.setAttribute("xmlns", "http://schemas.openxmlformats.org/package/2006/relationships");
                doc.appendChild(relationships);
            }

            // Get root element
            Element root = doc.getDocumentElement();
            
            // Add new signature origin relationship
            Element newRelationship = doc.createElement("Relationship");
            newRelationship.setAttribute("Type", "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin");
            newRelationship.setAttribute("Target", "/_xmlsignatures/origin.sigs");
            newRelationship.setAttribute("Id", "rId4");
            root.appendChild(newRelationship);

            // Transform DOM to XML string
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            String xmlString = writer.toString();

            // Add to zip
            addEntry(zip, ROOT_RELS_FILE, new ByteArrayInputStream(xmlString.getBytes(StandardCharsets.UTF_8)));

        } catch (ParserConfigurationException | TransformerException | SAXException e) {
            throw new IOException("Error processing XML relationships", e);
        }
    }

    //este es el root .rels que va en _rels del root - legacy string-based method
    private void updateRootRelationshipsLegacy(ZipOutputStream zip, ZipFile sourceZip) throws IOException {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");

        //aqui obtiene el archivo de los _rels para formarlo nuevamente
        ZipEntry relsEntry = sourceZip.getEntry(ROOT_RELS_FILE);
        if (relsEntry != null) {
            try (InputStream is = sourceZip.getInputStream(relsEntry)) {
                String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);

                if (content.contains("Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">")) {
                    //se quita el closure tag para lo que viene.
                    //TODO Usar estructuras de DOM para hacer esto, con strings es demasiado hacky
                    content = content.replace("</Relationships>", "");
                } else {
                    xml.append("<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n");
                }

                Pattern pattern = Pattern.compile("<Relationship[^>]+>");
                Matcher matcher = pattern.matcher(content);
                while (matcher.find()) {
                    String relationship = matcher.group(0);
                    // Skip any existing signature origin relationships
                    if (!relationship.contains("digital-signature/origin")) {
                        xml.append("  ").append(relationship).append("\n");
                    }
                }
            }
        }

        // Add signature origin relationship
        xml.append("  <Relationship ")
                .append("Type=\"http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin\" ")
                .append("Target=\"/_xmlsignatures/origin.sigs\" ")
                .append("Id=\"rId4\" />\n");
        xml.append("</Relationships>");

        addEntry(zip, ROOT_RELS_FILE, new ByteArrayInputStream(xml.toString().getBytes()));
    }

    public DSSDocument extend(DSSDocument document) {
        // Implementation for extending the signature level if needed
        return document;
    }

    private void cleanup() {
        try {
            if (originalDocx != null && originalDocx.exists()) {
                originalDocx.delete();
            }
            if (signedDocx != null && signedDocx.exists()) {
                signedDocx.delete();
            }
            if (tempDir != null && tempDir.toFile().exists()) {
                tempDir.toFile().delete();
            }
        } catch (Exception e) {
            LOG.warn("Error cleaning up temporary files", e);
        }
    }

    @Override
    public void close() {
        cleanup();
    }
}
