package cr.poc.firmador.sign;

import cr.poc.firmador.card.CardSignInfo;
import cr.poc.firmador.settings.Settings;
import cr.poc.firmador.settings.SettingsManager;
import cr.poc.firmador.utils.FirmadorUtils;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.invoke.MethodHandles;

@NoArgsConstructor
public class FirmadorCAdES extends CRSigner {
    final Logger LOG = LogManager.getLogger(MethodHandles.lookup().lookupClass());
    CAdESSignatureParameters parameters;
    private Settings settings = SettingsManager.getInstance().getAndCreateSettings();


    public DSSDocument sign(DSSDocument toSignDocument, CardSignInfo card) {
        CertificateVerifier verifier = this.getCertificateVerifier();
        CAdESService service = new CAdESService(verifier);
        this.parameters = new CAdESSignatureParameters();
        SignatureValue signatureValue = null;
        DSSDocument signedDocument = null;
        SignatureTokenConnection token = null;

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
            this.parameters.setSignatureLevel(this.settings.getCAdESLevel());
            this.parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
            this.parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            this.parameters.setSigningCertificate(certificate);
            OnlineTSPSource onlineTSPSource = new OnlineTSPSource("http://tsa.sinpe.fi.cr/tsaHttp/");
//            this.gui.nextStep("Obteniendo servicios TSP");
            service.setTspSource(onlineTSPSource);
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, this.parameters);
//            this.gui.nextStep("Obteniendo estructura de datos a firmar");
            signatureValue = token.sign(dataToSign, this.parameters.getDigestAlgorithm(), privateKey);
        } catch (Error | DSSException e) {
            this.LOG.error("Error al solicitar firma al dispositivo", e);
        }

        try {
//            this.gui.nextStep("Firmando estructura de datos");
            signedDocument = service.signDocument(toSignDocument, this.parameters, signatureValue);
//            this.gui.nextStep("Firmado del documento completo");
        } catch (Exception e) {
            this.LOG.error("Error al procesar información de firma avanzada", e);
            e.printStackTrace();
//            this.gui.showMessage("Aviso: no se ha podido agregar el sello de tiempo y la información de revocación porque es posible<br>que haya problemas de conexión a Internet o con los servidores del sistema de Firma Digital.<br>Detalle del error: " + FirmadorUtils.getRootCause(e) + "<br><br>Se ha agregado una firma básica solamente. No obstante, si el sello de tiempo resultara importante<br>para este documento, debería agregarse lo antes posible antes de enviarlo al destinatario.<br><br>Si lo prefiere, puede cancelar el guardado del documento firmado e intentar firmarlo más tarde.<br>");
            this.parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

            try {
                signedDocument = service.signDocument(toSignDocument, this.parameters, signatureValue);
            } catch (Exception var12) {
                this.LOG.error("Error al procesar información de firma avanzada en nivel fallback (sin Internet) a AdES-B", e);
            }
        }

        return signedDocument;
    }

    public DSSDocument extend(DSSDocument document) {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        CertificateVerifier verifier = this.getCertificateVerifier();
        CAdESService service = new CAdESService(verifier);
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
