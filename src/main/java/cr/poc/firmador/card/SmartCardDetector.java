package cr.poc.firmador.card;

import cr.poc.firmador.exception.UnsupportedArchitectureException;
import cr.poc.firmador.settings.Settings;
import cr.poc.firmador.settings.SettingsManager;
import cr.poc.firmador.sign.CRSigner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.nio.file.Files;
import java.nio.file.Path;

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
        List<CardSignInfo> cards;
        try {
            cards = this.readListSmartCard(pinInfo, true);
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


    public List<CardSignInfo> readListSmartCard(CardSignInfo pinInfo, boolean requirePin) throws Exception {
        List<CardSignInfo> cardInfo = new ArrayList<>();

        try {
            // Remove any escape characters from the library path
            String cleanLibPath = libraryPath.replace("\\ ", " ");

            // Verify library file exists
            File libFile = new File(cleanLibPath);
            if (!libFile.exists()) {
                throw new Exception("PKCS11 library not found: " + cleanLibPath);
            }

            // Create temporary config file
            configFile = createConfigFile(cleanLibPath);

            // Get the SunPKCS11 provider
            provider = Security.getProvider("SunPKCS11");
            if (provider == null) {
                throw new Exception("SunPKCS11 provider not available");
            }

            // Configure provider using the config file
            provider = provider.configure(configFile.getAbsolutePath());
            Security.addProvider(provider);

            // Initialize KeyStore
            keyStore = KeyStore.getInstance("PKCS11", provider);

            if (requirePin && pinInfo != null && pinInfo.getPin() != null) {
                keyStore.load(null, pinInfo.getPin().getPassword());
            } else {
                keyStore.load(null, null);
            }

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
            if (certificate.getBasicConstraints() == -1 &&
                    keyUsage != null &&
                    keyUsage[0] && // digitalSignature
                    keyUsage[1])   // nonRepudiation
            {
                // Parse certificate subject
                LdapName ldapName = new LdapName(
                        certificate.getSubjectX500Principal().getName("RFC1779")
                );

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

                String expires = new SimpleDateFormat("yyyy-MM-dd")
                        .format(certificate.getNotAfter());

                // Get token information
                String serialNumber = certificate.getSerialNumber().toString(16);

                // Create CardSignInfo object
                // Note: Some information like slot ID and token serial number
                // might need to be obtained differently with JCA

                //aqui lo que falta resolver es el slot ID y el serial number, esos son requeridos
//                new CardSignInfo(CardSignInfo.PKCS11TYPE, identification, firstName, lastName, commonName, organization, expires,
//                        certificate.getSerialNumber().toString(16), new String(tokenInfo.serialNumber), slotID);


                CardSignInfo info = new CardSignInfo(
                        CardSignInfo.PKCS11TYPE, identification,
                        firstName,
                        lastName,
                        commonName,
                        organization,
                        expires,
                        serialNumber,
                        "Unknown", // Token serial number needs different approach
                        0L        // Slot ID needs different approach
                );

                cardInfo.add(info);

                LOG.info(String.format(
                        "%s %s (%s), %s, %s (Expires: %s)",
                        firstName, lastName, identification,
                        organization, serialNumber, expires
                ));
            }

        } catch (Exception e) {
            LOG.error("Error processing certificate: " + e.getMessage());
        }
    }

    // Method to get token information (implementation depends on your needs)
    private String getTokenSerialNumber() throws Exception {
        // This would need to be implemented using PKCS11 provider-specific calls
        // or through JCA security properties
        return "Unknown";
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
//    public List<CardSignInfo> readListSmartCard() throws Throwable {
//        List<CardSignInfo> cardinfo = new ArrayList();
//        this.updateLib();
//        String functionList = "C_GetFunctionList";
//        CK_C_INITIALIZE_ARGS pInitArgs = new CK_C_INITIALIZE_ARGS();
//
//        PKCS11 pkcs11;
//        try {
//            pInitArgs.flags = 2L;
//            pkcs11 = PKCS11.getInstance(this.lib, functionList, pInitArgs, false);
//        } catch (PKCS11Exception e) {
//            this.LOG.debug("C_GetFunctionList didn't like CKF_OS_LOCKING_OK on pInitArgs", e);
//            pInitArgs.flags = 0L;
//            pkcs11 = PKCS11.getInstance(this.lib, functionList, pInitArgs, false);
//        }
//
//        CK_INFO info = pkcs11.C_GetInfo();
//        this.LOG.info("Interface: " + (new String(info.libraryDescription)).trim());
//        Boolean tokenPresent = true;
//
//        for (long slotID : pkcs11.C_GetSlotList(tokenPresent)) {
//            CK_SLOT_INFO slotInfo = pkcs11.C_GetSlotInfo(slotID);
//            this.LOG.debug("Slot " + slotID + ": " + (new String(slotInfo.slotDescription)).trim());
//            if ((slotInfo.flags & 1L) != 0L) {
//                try {
//                    CK_TOKEN_INFO tokenInfo = pkcs11.C_GetTokenInfo(slotID);
//                    this.LOG.info("Token: " + (new String(tokenInfo.label)).trim() + " (" + (new String(tokenInfo.serialNumber)).trim() + ")");
//                    CK_ATTRIBUTE[] pTemplate = new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(0L, 1L)};
//                    long ulMaxObjectCount = 32L;
//                    long hSession = pkcs11.C_OpenSession(slotID, 4L, (Object) null, (CK_NOTIFY) null);
//                    pkcs11.C_FindObjectsInit(hSession, pTemplate);
//                    long[] phObject = pkcs11.C_FindObjects(hSession, ulMaxObjectCount);
//                    pkcs11.C_FindObjectsFinal(hSession);
//
//                    for (long object : phObject) {
//                        CK_ATTRIBUTE[] pTemplate2 = new CK_ATTRIBUTE[]{new CK_ATTRIBUTE(17L), new CK_ATTRIBUTE(258L)};
//                        pkcs11.C_GetAttributeValue(hSession, object, pTemplate2);
//
//                        for (int i = 0; i < pTemplate2.length; i += 2) {
//                            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream((byte[]) pTemplate2[i].pValue));
//                            boolean[] keyUsage = certificate.getKeyUsage();
//                            if (certificate.getBasicConstraints() == -1 && keyUsage[0] && keyUsage[1]) {
//                                LdapName ldapName = new LdapName(certificate.getSubjectX500Principal().getName("RFC1779"));
//                                String firstName = "";
//                                String lastName = "";
//                                String identification = "";
//                                String commonName = "";
//                                String organization = "";
//
//                                for (Rdn rdn : ldapName.getRdns()) {
//                                    if (rdn.getType().equals("OID.2.5.4.5")) {
//                                        identification = rdn.getValue().toString();
//                                    }
//
//                                    if (rdn.getType().equals("OID.2.5.4.4")) {
//                                        lastName = rdn.getValue().toString();
//                                    }
//
//                                    if (rdn.getType().equals("OID.2.5.4.42")) {
//                                        firstName = rdn.getValue().toString();
//                                    }
//
//                                    if (rdn.getType().equals("CN")) {
//                                        commonName = rdn.getValue().toString();
//                                    }
//
//                                    if (rdn.getType().equals("O")) {
//                                        organization = rdn.getValue().toString();
//                                    }
//                                }
//
//                                String expires = (new SimpleDateFormat("yyyy-MM-dd")).format(certificate.getNotAfter());
//                                this.LOG.debug(firstName + " " + lastName + " (" + identification + "), " + organization + ", " + certificate.getSerialNumber().toString(16) + " [Token serial number: " + new String(tokenInfo.serialNumber) + "] (Expires: " + expires + ")");
//                                Object keyIdentifier = pTemplate2[i + 1];
//                                this.LOG.debug("Public/Private key pair identifier: " + keyIdentifier);
//                                cardinfo.add(new CardSignInfo(CardSignInfo.PKCS11TYPE, identification, firstName, lastName, commonName, organization, expires, certificate.getSerialNumber().toString(16), new String(tokenInfo.serialNumber), slotID));
//                            }
//                        }
//                    }
//
//                    pkcs11.C_CloseSession(hSession);
//                } catch (PKCS11Exception e) {
//                    if (!e.getLocalizedMessage().equals("CKR_TOKEN_NOT_RECOGNIZED")) {
//                        throw e;
//                    }
//
//                    this.LOG.info("Slot reports token is present but not recognized by the cryptoki library", e);
//                }
//            } else {
//                this.LOG.info("No token present in this slot");
//            }
//        }
//
//        return cardinfo;
//    }
}
