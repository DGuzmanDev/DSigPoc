package cr.poc.firmador.card;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyStore;
import java.util.List;
import java.util.Optional;

@Component
public class SmartCardManager {

    private SmartCardDetector smartCardDetector;

    @Autowired
    public SmartCardManager(SmartCardDetector smartCardDetector) {
        this.smartCardDetector = smartCardDetector;
    }

    public List<CardSignInfo> readCertificatesInfo(Optional<KeyStore.PasswordProtection> password) throws Exception {
        if (password.isPresent()) {
            return smartCardDetector.readPrivateCertsWithLogin(password.get());
        } else {
            return smartCardDetector.readPublicCertificatesInfo();
        }
    }
}
