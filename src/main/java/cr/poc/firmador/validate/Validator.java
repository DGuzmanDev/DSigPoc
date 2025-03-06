package cr.poc.firmador.validate;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.identifier.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Validator {
    private SignedDocumentValidator documentValidator;

    public Validator(String fileName) {
        CertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.addCertificate(DSSUtils.loadCertificate(this.getClass().getClassLoader().getResourceAsStream("certs/CA RAIZ NACIONAL - COSTA RICA v2.crt")));
        trustedCertSource.addCertificate(DSSUtils.loadCertificate(this.getClass().getClassLoader().getResourceAsStream("certs/CA RAIZ NACIONAL COSTA RICA.cer")));
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setTrustedCertSources(new CertificateSource[]{trustedCertSource});
        cv.setOcspSource(new OnlineOCSPSource());
        cv.setCrlSource(new OnlineCRLSource());
        cv.setAIASource(new DefaultAIASource());
        FileDocument fileDocument = new FileDocument(fileName);
        this.documentValidator = SignedDocumentValidator.fromDocument(fileDocument);
        this.documentValidator.setCertificateVerifier(cv);
        this.documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_ALL);
        this.documentValidator.setTokenIdentifierProvider(new UserFriendlyIdentifierProvider());
        if (fileDocument.getMimeType() == MimeTypeEnum.XML) {
            String electronicReceipt = (new XMLDocumentValidator(fileDocument)).getRootElement().getDocumentElement().getTagName();
            String[] receiptTypes = new String[]{"FacturaElectronica", "TiqueteElectronico", "NotaDebitoElectronica", "NotaCreditoElectronica", "FacturaElectronicaCompra", "FacturaElectronicaExportacion", "MensajeReceptor"};
            if (Arrays.asList(receiptTypes).contains(electronicReceipt)) {
                SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
                Map<String, DSSDocument> signaturePoliciesById = new HashMap();
                signaturePoliciesById.put("https://atv.hacienda.go.cr/ATV/ComprobanteElectronico/docs/esquemas/2016/v4.3/Resoluci%C3%B3n_General_sobre_disposiciones_t%C3%A9cnicas_comprobantes_electr%C3%B3nicos_para_efectos_tributarios.pdf", new InMemoryDocument(this.getClass().getClassLoader().getResourceAsStream("dgt/Resolución_General_sobre_disposiciones_técnicas_comprobantes_electrónicos_para_efectos_tributarios.pdf")));
                signaturePoliciesById.put("https://www.hacienda.go.cr/ATV/ComprobanteElectronico/docs/esquemas/2016/v4.3/Resoluci%C3%B3n_General_sobre_disposiciones_t%C3%A9cnicas_comprobantes_electr%C3%B3nicos_para_efectos_tributarios.pdf", new InMemoryDocument(this.getClass().getClassLoader().getResourceAsStream("dgt/Resolución_General_sobre_disposiciones_técnicas_comprobantes_electrónicos_para_efectos_tributarios.pdf")));
                signaturePoliciesById.put("https://www.hacienda.go.cr/ATV/ComprobanteElectronico/docs/esquemas/2016/v4.2/ResolucionComprobantesElectronicosDGT-R-48-2016_4.2.pdf", new InMemoryDocument(this.getClass().getClassLoader().getResourceAsStream("dgt/ResolucionComprobantesElectronicosDGT-R-48-2016_4.2.pdf")));
                signaturePoliciesById.put("https://www.hacienda.go.cr/ATV/ComprobanteElectronico/docs/esquemas/2016/v4.1/Resolucion_Comprobantes_Electronicos_DGT-R-48-2016_v4.1.pdf", new InMemoryDocument(this.getClass().getClassLoader().getResourceAsStream("dgt/Resolucion_Comprobantes_Electronicos_DGT-R-48-2016_v4.1.pdf")));
                signaturePoliciesById.put("https://www.hacienda.go.cr/ATV/ComprobanteElectronico/docs/esquemas/2016/v4/Resolucion%20Comprobantes%20Electronicos%20%20DGT-R-48-2016.pdf", new InMemoryDocument(this.getClass().getClassLoader().getResourceAsStream("dgt/Resolucion Comprobantes Electronicos  DGT-R-48-2016.pdf")));
                signaturePolicyProvider.setSignaturePoliciesById(signaturePoliciesById);
                this.documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);
            }
        }

    }

    public Reports getReports() {
        Reports reports = this.documentValidator.validateDocument();
        return reports;
    }

    public boolean isSigned() {
        return !this.documentValidator.getSignatures().isEmpty();
    }
}
