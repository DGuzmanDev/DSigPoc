package cr.poc.firmador.sign;

import cr.poc.firmador.card.CardSignInfo;
import cr.poc.firmador.settings.Settings;
import cr.poc.firmador.settings.SettingsManager;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.XPathEnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.invoke.MethodHandles;
import java.util.Arrays;

@NoArgsConstructor
public class FirmadorXAdES extends CRSigner {
    final Logger LOG = LogManager.getLogger(MethodHandles.lookup().lookupClass());
    XAdESSignatureParameters parameters;
    private Settings settings = SettingsManager.getInstance().getAndCreateSettings();


    public DSSDocument sign(DSSDocument toSignDocument, CardSignInfo card) {
        CertificateVerifier verifier = this.getCertificateVerifier();
        XAdESService service = new XAdESService(verifier);
        this.parameters = new XAdESSignatureParameters();
        SignatureValue signatureValue = null;
        DSSDocument signedDocument = null;
        SignatureTokenConnection token = null;
//        this.gui.nextStep("Obteniendo servicios de verificación de certificados");

        try {
            token = this.getSignatureConnection(card);
        } catch (AlertException | Error | DSSException e) {
            this.LOG.error("Error al conectar con el dispositivo", e);
            return null;
        }

        DSSPrivateKeyEntry privateKey = null;

        try {
            privateKey = this.getPrivateKey(token);
//            this.gui.nextStep("Obteniendo manejador de llaves privadas");
        } catch (Exception e) {
            this.LOG.error("Error al acceder al objeto de llave del dispositivo", e);
            return null;
        }

        try {
//            this.gui.nextStep("Obteniendo certificados de la tarjeta");
            CertificateToken certificate = privateKey.getCertificate();
            this.parameters.setSignatureLevel(this.settings.getXAdESLevel());
            this.parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            this.parameters.setSigningCertificate(certificate);
            this.parameters.setSigningCertificateDigestMethod(this.parameters.getDigestAlgorithm());
            this.parameters.setPrettyPrint(true);
            OnlineTSPSource onlineTSPSource = new OnlineTSPSource("http://tsa.sinpe.fi.cr/tsaHttp/");
//            this.gui.nextStep("Obteniendo servicios TSP");
            service.setTspSource(onlineTSPSource);
            if (toSignDocument.getMimeType() == MimeTypeEnum.XML) {
                this.parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
                this.parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
                String electronicReceipt = (new XMLDocumentValidator(toSignDocument)).getRootElement().getDocumentElement().getTagName();
                String[] receiptTypes = new String[]{"FacturaElectronica", "TiqueteElectronico", "NotaDebitoElectronica", "NotaCreditoElectronica", "FacturaElectronicaCompra", "FacturaElectronicaExportacion", "MensajeReceptor"};
                if (Arrays.asList(receiptTypes).contains(electronicReceipt)) {
                    Policy policy = new Policy();
                    policy.setId("https://atv.hacienda.go.cr/ATV/ComprobanteElectronico/docs/esquemas/2016/v4.3/Resoluci%C3%B3n_General_sobre_disposiciones_t%C3%A9cnicas_comprobantes_electr%C3%B3nicos_para_efectos_tributarios.pdf");
                    policy.setDigestAlgorithm(this.parameters.getDigestAlgorithm());
                    policy.setDigestValue(Utils.fromBase64("0h7Q3dFHhu0bHbcZEgVc07cEcDlquUeG08HG6Iototo="));
                    this.parameters.bLevel().setSignaturePolicy(policy);
                }
            } else {
                this.parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
            }

            DSSReference dssReference = new DSSReference();
            dssReference.setTransforms(Arrays.asList(new XPathEnvelopedSignatureTransform()));
            dssReference.setContents(toSignDocument);
            dssReference.setId("r-" + this.parameters.getDeterministicId() + "-1");
            dssReference.setUri("");
            dssReference.setDigestMethodAlgorithm(this.parameters.getDigestAlgorithm());
            this.parameters.setReferences(Arrays.asList(dssReference));
            this.parameters.setEn319132(false);
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, this.parameters);
//            this.gui.nextStep("Obteniendo estructura de datos a firmar");
            signatureValue = token.sign(dataToSign, this.parameters.getDigestAlgorithm(), privateKey);
        } catch (Error | DSSException e) {
            this.LOG.error("Error al solicitar firma al dispositivo", e);
//            this.gui.showError(FirmadorUtils.getRootCause(e));
        }

        try {
//            this.gui.nextStep("Firmando estructura de datos");
            signedDocument = service.signDocument(toSignDocument, this.parameters, signatureValue);
//            this.gui.nextStep("Firmado del documento completo");
        } catch (Exception e) {
            this.LOG.error("Error al procesar información de firma avanzada", e);
            e.printStackTrace();
//            this.gui.showMessage("Aviso: no se ha podido agregar el sello de tiempo y la información de revocación porque es posible<br>que haya problemas de conexión a Internet o con los servidores del sistema de Firma Digital.<br>Detalle del error: " + FirmadorUtils.getRootCause(e) + "<br><br>Se ha agregado una firma básica solamente. No obstante, si el sello de tiempo resultara importante<br>para este documento, debería agregarse lo antes posible antes de enviarlo al destinatario.<br><br>Si lo prefiere, puede cancelar el guardado del documento firmado e intentar firmarlo más tarde.<br>");
            this.parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

            try {
                signedDocument = service.signDocument(toSignDocument, this.parameters, signatureValue);
            } catch (Exception var14) {
                this.LOG.error("Error al procesar información de firma avanzada en nivel fallback (sin Internet) a AdES-B", e);
//                this.gui.showError(FirmadorUtils.getRootCause(e));
            }
        }

        return signedDocument;
    }

    public DSSDocument extend(DSSDocument document) {
        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        parameters.setPrettyPrint(true);
        CertificateVerifier verifier = this.getCertificateVerifier();
        XAdESService service = new XAdESService(verifier);
        OnlineTSPSource onlineTSPSource = new OnlineTSPSource("http://tsa.sinpe.fi.cr/tsaHttp/");
        service.setTspSource(onlineTSPSource);
        DSSDocument extendedDocument = null;

        try {
            extendedDocument = service.extendDocument(document, parameters);
        } catch (Exception e) {
            this.LOG.error("Error al procesar información para al ampliar el nivel de firma avanzada a LTA (sello adicional)", e);
            e.printStackTrace();
//            this.gui.showMessage("Aviso: no se ha podido agregar el sello de tiempo y la información de revocación porque es posible<br>que haya problemas de conexión a Internet o con los servidores del sistema de Firma Digital.<br>Detalle del error: " + FirmadorUtils.getRootCause(e) + "<br><br>Inténtelo de nuevo más tarde. Si el problema persiste, compruebe su conexión o verifique<br>que no se trata de un problema de los servidores de Firma Digital o de un error de este programa.<br>");
        }

        return extendedDocument;
    }
}
