package cr.poc.firmador.card;

import com.sun.jna.Memory;
import com.sun.jna.ptr.LongByReference;
import cr.poc.firmador.exception.UnsupportedArchitectureException;
import cr.poc.firmador.settings.Settings;
import cr.poc.firmador.settings.SettingsManager;
import cr.poc.firmador.sign.CRSigner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class SmartCardDetector implements AutoCloseable {
    final Logger LOG = LogManager.getLogger(MethodHandles.lookup().lookupClass());
    protected Settings settings = SettingsManager.getInstance().getAndCreateSettings();
    private String libraryPath;
    private Provider provider;
    private KeyStore keyStore;
    private File configFile;

    public SmartCardDetector() {
        this.updateLib();
    }

    public SmartCardDetector(String libraryPath) {
        this.libraryPath = libraryPath;
    }


    public void updateLib() {
        this.libraryPath = CRSigner.getPkcs11Lib();
    }

    public List<CardSignInfo> readSaveListSmartCard(CardSignInfo pinInfo) throws Throwable {
        List<CardSignInfo> cards = Collections.emptyList();
        try {
            if (pinInfo != null && pinInfo.getPin() != null) {
                // If PIN is provided, use readListSmartCard
                cards = this.readListSmartCard(pinInfo);
            } else {
                // If no PIN is provided, use readPublicCertificateInfo
                cards = readPublicCertificateInfo();
            }
        } catch (Throwable e) {
            this.LOG.info("readListSmartCard thrown", e);
            if (e.getMessage().toString().contains("incompatible architecture")) {
                throw new UnsupportedArchitectureException("Java para ARM detectado. Debe instalar Java para Intel para usar tarjetas de Firma Digital.", e);
            }
            cards = new ArrayList();
        }

        for (String pkcs12 : this.settings.pKCS12File) {
            File f = new File(pkcs12);
            if (f.exists()) {
                cards.add(new CardSignInfo(CardSignInfo.PKCS12TYPE, pkcs12, f.getName()));
            }
        }

        return cards;
    }

    public List<CardSignInfo> readListSmartCard(CardSignInfo pinInfo) throws Exception {
        List<CardSignInfo> cardInfo = new ArrayList<>();

        try {
            // Debug: List available providers
            listAvailableProviders();

            String cleanLibPath = libraryPath.replace("\\ ", " ");
            File libFile = new File(cleanLibPath);
            if (!libFile.exists()) {
                throw new Exception("PKCS11 library not found: " + cleanLibPath);
            }

            configFile = createConfigFile(cleanLibPath);
            provider = Security.getProvider("SunPKCS11");
            if (provider == null) {
                throw new Exception("SunPKCS11 provider not available");
            }

            provider = provider.configure(configFile.getAbsolutePath());
            Security.addProvider(provider);

            keyStore = KeyStore.getInstance("PKCS11", provider);

            try {
                // Handle PIN
                char[] pin = (pinInfo != null && pinInfo.getPin() != null) ? pinInfo.getPin().getPassword() : null;

                // Load the keystore with PIN
                keyStore.load(null, pin);

                // Process certificates
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    try {
                        Certificate cert = keyStore.getCertificate(alias);
                        if (cert instanceof X509Certificate) {
                            X509Certificate x509Cert = (X509Certificate) cert;
                            processX509Certificate(x509Cert, cardInfo);
                        }
                    } catch (Exception e) {
                        LOG.warn("Error processing certificate for alias " + alias + ": " + e.getMessage());
                        continue;
                    }
                }

            } catch (Exception e) {
                if (e.getMessage() != null && (e.getMessage().contains("CKR_PIN_REQUIRED") || e.getMessage().contains("token login required"))) {
                    LOG.debug("PIN required for this operation");
                    return cardInfo;
                }
                throw e;
            }

        } catch (Exception e) {
            LOG.error("Error reading smart card: " + e.getMessage(), e);
            throw e;
        }

        return cardInfo;
    }

    private File createConfigFile(String libraryPath) throws IOException {
        String config = String.format("""
                name = SmartCard
                library = %s
                attributes(*,*,*) = {
                    CKA_TOKEN = true
                }
                """, libraryPath);

        // Create temporary file with .cfg extension
        Path configPath = Files.createTempFile("pkcs11-", ".cfg");
        File configFile = configPath.toFile();
        configFile.deleteOnExit();

        // Write configuration to file
        try (FileWriter writer = new FileWriter(configFile)) {
            writer.write(config);
        }

        LOG.debug("Created PKCS11 config file: " + configFile.getAbsolutePath());
        return configFile;
    }

    private void processX509Certificate(X509Certificate certificate, List<CardSignInfo> cardInfo) {
        try {
            boolean[] keyUsage = certificate.getKeyUsage();

            // Check if certificate is for signing
            if (certificate.getBasicConstraints() == -1 && keyUsage != null && keyUsage[0] && // digitalSignature
                    keyUsage[1])   // nonRepudiation
            {
                // Parse certificate subject
                LdapName ldapName = new LdapName(certificate.getSubjectX500Principal().getName("RFC1779"));

                String firstName = "";
                String lastName = "";
                String identification = "";
                String commonName = "";
                String organization = "";

                // Extract certificate information
                for (Rdn rdn : ldapName.getRdns()) {
                    switch (rdn.getType()) {
                        case "OID.2.5.4.5":
                            identification = rdn.getValue().toString();
                            break;
                        case "OID.2.5.4.4":
                            lastName = rdn.getValue().toString();
                            break;
                        case "OID.2.5.4.42":
                            firstName = rdn.getValue().toString();
                            break;
                        case "CN":
                            commonName = rdn.getValue().toString();
                            break;
                        case "O":
                            organization = rdn.getValue().toString();
                            break;
                    }
                }

                String expires = new SimpleDateFormat("yyyy-MM-dd").format(certificate.getNotAfter());

                // Get token information
                String serialNumber = certificate.getSerialNumber().toString(16);

                // Create CardSignInfo object
                // Note: Some information like slot ID and token serial number
                // might need to be obtained differently with JCA

                //aqui lo que falta resolver es el slot ID y el serial number, esos son requeridos
//                new CardSignInfo(CardSignInfo.PKCS11TYPE, identification, firstName, lastName, commonName, organization, expires,
//                        certificate.getSerialNumber().toString(16), new String(tokenInfo.serialNumber), slotID);


                CardSignInfo info = new CardSignInfo(CardSignInfo.PKCS11TYPE, identification, firstName, lastName, commonName, organization, expires, serialNumber, "Unknown", // Token serial number needs different approach
                        0L        // Slot ID needs different approach
                );

                cardInfo.add(info);

                LOG.info(String.format("%s %s (%s), %s, %s (Expires: %s)", firstName, lastName, identification, organization, serialNumber, expires));
            }

        } catch (Exception e) {
            LOG.error("Error processing certificate: " + e.getMessage());
        }
    }

    private List<CardSignInfo> readPublicCertificateInfo() throws Exception {
        List<CardSignInfo> cards = new ArrayList<>();
        PKCS11Native pkcs11 = PKCS11Native.INSTANCE;

        // Initialize PKCS11
        long rv = pkcs11.C_Initialize(null);
        if (rv != 0) {
            throw new Exception("Failed to initialize PKCS11 library: " + rv);
        }

        try {
            // Get slots with tokens present
            LongByReference slotCount = new LongByReference();
            rv = pkcs11.C_GetSlotList(true, null, slotCount);
            if (rv != 0) {
                throw new Exception("Failed to get slot count: " + rv);
            }

            long[] slots = new long[(int) slotCount.getValue()];
            rv = pkcs11.C_GetSlotList(true, slots, slotCount);
            if (rv != 0) {
                throw new Exception("Failed to get slot list: " + rv);
            }

            // Process each slot
            for (long slot : slots) {
                processSlot(pkcs11, slot, cards);
            }
        } finally {
            pkcs11.C_Finalize(null);
        }

        return cards;
    }

    private void processSlot(PKCS11Native pkcs11, long slot, List<CardSignInfo> cards) {
        // Get token info
        PKCS11Native.TokenInfo tokenInfo = new PKCS11Native.TokenInfo();
        long rv = pkcs11.C_GetTokenInfo(slot, tokenInfo);
        if (rv != 0) {
            LOG.warn("Failed to get token info for slot " + slot);
            return;
        }

        String serialNumber = new String(tokenInfo.serialNumber).trim();
        String label = new String(tokenInfo.label).trim();
        String model = new String(tokenInfo.model).trim();

        LOG.info("Processing token - Serial: {}, Label: {}, Model: {}", serialNumber, label, model);

        // Open read-only session (no login required)
        LongByReference session = new LongByReference();
        rv = pkcs11.C_OpenSession(slot, PKCS11Native.CKF_SERIAL_SESSION, null, null, session);
        if (rv != 0) {
            LOG.warn("Failed to open session on slot " + slot);
            return;
        }

        try {
            readCertificatesFromSession(pkcs11, session.getValue(), slot, serialNumber, cards);
        } finally {
            pkcs11.C_CloseSession(session.getValue());
        }
    }

    private void readCertificatesFromSession(PKCS11Native pkcs11, long session, long slot, String tokenSerial, List<CardSignInfo> cards) {
        // Find X.509 certificates
        PKCS11Native.CKAttribute[] template = PKCS11Native.CKAttribute.createTemplate(new PKCS11Native.CKAttribute(PKCS11Native.CKA_CLASS, PKCS11Native.CKO_CERTIFICATE), new PKCS11Native.CKAttribute(PKCS11Native.CKA_CERTIFICATE_TYPE, PKCS11Native.CKC_X_509));

        long rv = pkcs11.C_FindObjectsInit(session, template, template.length);
        if (rv != 0) {
            LOG.warn("Failed to initialize object finding");
            return;
        }

        try {
            long[] objects = new long[32];
            LongByReference count = new LongByReference();

            rv = pkcs11.C_FindObjects(session, objects, objects.length, count);
            if (rv != 0) {
                LOG.warn("Failed to find objects");
                return;
            }

            for (int i = 0; i < count.getValue(); i++) {
                processCertificate(pkcs11, session, objects[i], slot, tokenSerial, cards);
            }
        } finally {
            pkcs11.C_FindObjectsFinal(session);
        }
    }

    private void processCertificate(PKCS11Native pkcs11, long session, long object, long slot, String tokenSerial, List<CardSignInfo> cards) {
        try {
            byte[] certBytes = getCertificateBytes(pkcs11, session, object);
            if (certBytes == null) return;

            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certBytes));

            // Only process non-CA certificates with digital signature usage
            if (cert.getBasicConstraints() != -1) return;

            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage == null || !keyUsage[0] || !keyUsage[1]) return;

            // Extract certificate information and create CardSignInfo
            LdapName ldapName = new LdapName(cert.getSubjectX500Principal().getName());
            String firstName = "", lastName = "", identification = "", commonName = "", organization = "";

            for (Rdn rdn : ldapName.getRdns()) {
                String type = rdn.getType().toLowerCase();
                String value = rdn.getValue().toString();
                
                switch (type) {
                    // Handle both OID and common name formats
                    case "oid.2.5.4.42":
                    case "givenname":
                        firstName = value;
                        break;
                        
                    case "oid.2.5.4.4":
                    case "surname":
                        lastName = value;
                        break;
                        
                    case "oid.2.5.4.5":
                    case "serialnumber":
                        identification = value;
                        break;
                        
                    case "cn":
                    case "oid.2.5.4.3":
                        commonName = value;
                        break;
                        
                    case "o":
                    case "oid.2.5.4.10":
                        organization = value;
                        break;
                        
                    default:
                        LOG.debug("Unhandled certificate attribute - Type: {}, Value: {}", type, value);
                }
            }

            SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
            String expires = dateFormat.format(cert.getNotAfter());

            cards.add(new CardSignInfo(
                CardSignInfo.PKCS11TYPE,
                identification,
                firstName,
                lastName,
                commonName,
                organization,
                expires,
                cert.getSerialNumber().toString(16),
                tokenSerial,
                slot
            ));

        } catch (Exception e) {
            LOG.warn("Failed to process certificate", e);
        }
    }

    private byte[] getCertificateBytes(PKCS11Native pkcs11, long session, long object) {
        PKCS11Native.CKAttribute[] template = PKCS11Native.CKAttribute.createTemplate(new PKCS11Native.CKAttribute(PKCS11Native.CKA_VALUE));

        // Get certificate size
        long rv = pkcs11.C_GetAttributeValue(session, object, template, template.length);
        if (rv != 0) return null;

        // Allocate memory and get actual certificate data
        template[0].pValue = new Memory(template[0].ulValueLen);
        rv = pkcs11.C_GetAttributeValue(session, object, template, template.length);
        if (rv != 0) return null;

        return template[0].pValue.getByteArray(0, (int) template[0].ulValueLen);
    }

    private void listAvailableProviders() {
        LOG.debug("=== Available Security Providers ===");

        // List all providers
        for (Provider p : Security.getProviders()) {
            LOG.debug(String.format("Provider: %s (version %.2f)", p.getName(), p.getVersion()));

            // List all services for this provider
            p.getServices().stream().filter(s -> s.getType().contains("PKCS11") || s.getAlgorithm().contains("PKCS11")).forEach(s -> LOG.debug(String.format("  - Type: %s, Algorithm: %s", s.getType(), s.getAlgorithm())));
        }

        // Specifically check for SunPKCS11 provider
        Provider sunPkcs11 = Security.getProvider("SunPKCS11");
        if (sunPkcs11 != null) {
            LOG.debug("SunPKCS11 provider is available");
            LOG.debug("Class: " + sunPkcs11.getClass().getName());
        } else {
            LOG.debug("SunPKCS11 provider is NOT available");
        }

        LOG.debug("===================================");
    }


    @Override
    public void close() {
        if (provider != null) {
            Security.removeProvider(provider.getName());
        }
        if (configFile != null && configFile.exists()) {
            configFile.delete();
        }
    }
}
