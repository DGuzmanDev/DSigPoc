package cr.poc.firmador.sign;

import cr.poc.firmador.card.CardSignInfo;
import cr.poc.firmador.settings.Settings;
import cr.poc.firmador.settings.SettingsManager;
import cr.poc.firmador.utils.FirmadorUtils;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;

@NoArgsConstructor
public class CRSigner {
    final Logger LOG = LogManager.getLogger(MethodHandles.lookup().lookupClass());
    public static final String TSA_URL = "http://tsa.sinpe.fi.cr/tsaHttp/";


    protected DSSPrivateKeyEntry getPrivateKey(SignatureTokenConnection signingToken) {
        DSSPrivateKeyEntry privateKey = null;
        List<DSSPrivateKeyEntry> keys = null;

        try {
            keys = signingToken.getKeys();
        } catch (Throwable error) {
            Throwable te = FirmadorUtils.getRootCause(error);
            String msg = error.getCause().toString();
            this.LOG.error("Error " + te.getLocalizedMessage() + " obteniendo manejador de llaves privadas de la tarjeta", error);
            if (te.getLocalizedMessage().equals("CKR_PIN_INCORRECT")) {
                throw error;
            }

            if (te.getLocalizedMessage().equals("CKR_GENERAL_ERROR") && error.getCause().toString().contains("Unable to instantiate PKCS11")) {
                throw error;
            }

            if (te.getLocalizedMessage().equals("CKR_TOKEN_NOT_RECOGNIZED")) {
                this.LOG.info(te.getLocalizedMessage() + " (dispositivo de firma no reconocido)", error);
                return null;
            }

            if (msg.contains("but token only has 0 slots")) {
                throw error;
            }
        }

        if (keys != null) {
            for (DSSPrivateKeyEntry candidatePrivateKey : keys) {
                if (candidatePrivateKey.getCertificate().checkKeyUsage(KeyUsageBit.NON_REPUDIATION)) {
                    privateKey = candidatePrivateKey;
                    break;
                }
            }
        }

        return privateKey;
    }

    public static String getPkcs11Lib() {
        String osName = System.getProperty("os.name").toLowerCase();
        Settings settings = SettingsManager.getInstance().getAndCreateSettings();

        if (settings.extraPKCS11Lib != null && !settings.extraPKCS11Lib.isEmpty()) {
            return settings.extraPKCS11Lib;
        } else if (osName.contains("mac")) {
            return "/Library/Application Support/Athena/libASEP11.dylib";
        } else if (osName.contains("linux")) {
            return "/usr/lib/x64-athena/libASEP11.so";
        } else {
            return osName.contains("windows") ?
                    System.getenv("SystemRoot") + "\\System32\\asepkcs.dll" : "";
        }
    }

    public SignatureTokenConnection getSignatureConnection(CardSignInfo card) {
        SignatureTokenConnection signingToken = null;

        try {
            if (card.getCardType() == CardSignInfo.PKCS12TYPE) {
                // In this case the CardSignInfo.getTokenSerialNumber actually has a file absolute path to an PKCS12 key store
                signingToken = new Pkcs12SignatureToken(card.getTokenSerialNumber(), card.getPin());
            } else {
                //TODO: Hacer dinamico el slot #, este mae sigue siendo "quemado" por el high level API
                // ero se puede lograr con el approach de los public certs usando JNA
                signingToken = new Pkcs11SignatureToken(getPkcs11Lib(), card.getPin(), (int) card.getSlotID());
            }
        } catch (Throwable e) {
            this.LOG.error("Error al obtener la conexión de firma", e);
        }

        return signingToken;
    }

    private void addCertificateToSource(CertificateSource source, String certPath) {
        try (InputStream certStream = this.getClass().getClassLoader().getResourceAsStream(certPath)) {
            if (certStream == null) {
                LOG.error("Certificate file not found: {}", certPath);
                return;
            }
            source.addCertificate(DSSUtils.loadCertificate(certStream));
        } catch (IOException | DSSException e) {
            LOG.error("Failed to load certificate from {}: {}", certPath, e.getMessage());
        }
    }

    public CertificateVerifier getCertificateVerifier() {
        //For debugging
//        listAvailableCertificates();

        CertificateSource trustedCertSource = new CommonTrustedCertificateSource();

        // Add root certificates
        addCertificateToSource(trustedCertSource, "certs/CA RAIZ NACIONAL - COSTA RICA v2.crt");
        addCertificateToSource(trustedCertSource, "certs/CA RAIZ NACIONAL COSTA RICA.cer");

        CertificateSource adjunctCertSource = new CommonCertificateSource();

        // Add intermediate certificates
        addCertificateToSource(adjunctCertSource, "certs/CA POLITICA PERSONA FISICA - COSTA RICA v2.crt");
        addCertificateToSource(adjunctCertSource, "certs/CA POLITICA PERSONA JURIDICA - COSTA RICA v2.crt");
        addCertificateToSource(adjunctCertSource, "certs/CA POLITICA SELLADO DE TIEMPO - COSTA RICA v2.crt");
        addCertificateToSource(adjunctCertSource, "certs/CA SINPE - PERSONA FISICA v2(1).crt");
        addCertificateToSource(adjunctCertSource, "certs/CA SINPE - PERSONA FISICA v2(2).crt");
        addCertificateToSource(adjunctCertSource, "certs/CA SINPE - PERSONA JURIDICA v2(1).crt");
        addCertificateToSource(adjunctCertSource, "certs/CA SINPE - PERSONA JURIDICA v2(2).crt");
        addCertificateToSource(adjunctCertSource, "certs/TSA SINPE v3.cer");

        CommonCertificateVerifier cv = new CommonCertificateVerifier();
        cv.setTrustedCertSources(new CertificateSource[]{trustedCertSource});
        cv.setAdjunctCertSources(new CertificateSource[]{adjunctCertSource});
        cv.setCrlSource(new OnlineCRLSource());
        cv.setOcspSource(new OnlineOCSPSource());
        cv.setAIASource(new DefaultAIASource());
        cv.setRevocationFallback(true);
        return cv;
    }

    private void listAvailableCertificates() {
        try {
            URI uri = getClass().getClassLoader().getResource("certs").toURI();
            Path myPath;
            if (uri.getScheme().equals("jar")) {
                FileSystem fileSystem = FileSystems.newFileSystem(uri, Collections.<String, Object>emptyMap());
                myPath = fileSystem.getPath("/certs");
            } else {
                myPath = Paths.get(uri);
            }
            Files.walk(myPath, 1).forEach(path -> {
                LOG.info("Found certificate file: {}", path);
            });
        } catch (Exception e) {
            LOG.error("Failed to list certificates: {}", e.getMessage());
        }
    }
}
