package cr.poc.firmador.card;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.invoke.MethodHandles;
import java.security.KeyStore;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CardSignInfo {

    final Logger LOG = LogManager.getLogger(MethodHandles.lookup().lookupClass());

    public static int PKCS11TYPE = 1;
    public static int PKCS12TYPE = 2;
    public static int ONLYPIN = 3;
    private String identification;
    private String firstName;
    private String lastName;
    private String commonName;
    private String organization;
    private String expires;
    private String tokenSerialNumber;
    private long slotID = -1L;
    private KeyStore.PasswordProtection pin;
    private int cardType;

    public CardSignInfo(KeyStore.PasswordProtection password) {
        this.setPin(password);
        this.cardType = ONLYPIN;
    }

    public CardSignInfo(int cardType, String path, String identification) {
        this.cardType = cardType;
        this.tokenSerialNumber = path;
        this.identification = identification;
        this.firstName = "NOMBRE";
        this.lastName = "DE LA PERSONA";
        this.commonName = "NOMBRE DE LA PERSONA (TIPO DE CERTIFICADO)";
        this.organization = "TIPO DE PERSONA";
        this.expires = "";
    }

    public CardSignInfo(int cardType, String identification, String firstName, String lastName, String commonName, String organization, String expires, String certSerialNumber, String tokenSerialNumber, long slotID) {
        this.cardType = cardType;
        this.identification = identification;
        this.firstName = firstName;
        this.lastName = lastName;
        this.commonName = commonName;
        this.organization = organization;
        this.expires = expires;
        this.tokenSerialNumber = tokenSerialNumber;
        this.slotID = slotID;
    }

    public String getDisplayInfo() {
        return this.cardType == PKCS11TYPE ? this.firstName + " " + this.lastName + " (" + this.identification + ") (Expira: " + this.expires + ")" : this.identification;
    }

    public boolean isValid() {
        return this.pin.getPassword() != null && this.pin.getPassword().length != 0;
    }

    public void destroyPin() {
        try {
            this.pin.destroy();
        } catch (Exception e) {
            this.LOG.error("Error destruyendo el pin", e);
            e.printStackTrace();
        }
    }
}
