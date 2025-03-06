package cr.poc.firmador.settings;

import cr.poc.firmador.config.ConfigListener;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextPosition;

import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Settings {

    private List<ConfigListener> listeners = new ArrayList();
    public String releaseUrlCheck = "https://firmador.libre.cr/version.txt";
    public String baseUrl = "https://firmador.libre.cr";
    public String releaseUrl = "https://firmador.libre.cr/firmador.jar";
    public String releaseSnapshotUrl = "https://firmador.libre.cr/firmador-en-pruebas.jar";
    public String checksumUrl = "https://firmador.libre.cr/firmador.jar.sha256";
    public String checksumSnapshotUrl = "https://firmador.libre.cr/firmador-en-pruebas.jar.sha256";
    public String defaultDevelopmentVersion = "Desarrollo";
    public boolean withoutVisibleSign = false;
    public boolean overwriteSourceFile = false;
    public String reason = "";
    public String place = "";
    public String contact = "";
    public String dateFormat = "dd/MM/yyyy hh:mm:ss a";
    public String defaultSignMessage = "Esta es una representación gráfica únicamente,\nverifique la validez de la firma.";
    public Integer signWidth = 133;
    public Integer signHeight = 33;
    public Integer fontSize = 7;
    public String font = "SansSerif";
    public String fontColor = "#000000";
    public String backgroundColor = "transparente";
    public String extraPKCS11Lib = null;
    public Integer signX = 198;
    public Integer signY = 0;
    public String image = null;
    public String fontAlignment = "RIGHT";
    public boolean showLogs = false;
    public Integer pageNumber = 1;
    public Integer portNumber = 3516;
    public String pAdESLevel = "LTA";
    public String xAdESLevel = "LTA";
    public String cAdESLevel = "LTA";
    public List<String> pKCS12File = new ArrayList();
    public List<String> activePlugins = new ArrayList();
    public List<String> availablePlugins = new ArrayList();
    public float pDFImgScaleFactor = 1.0F;

    public Settings() {
        this.activePlugins.add("cr.libre.firmador.plugins.DummyPlugin");
        this.activePlugins.add("cr.libre.firmador.plugins.CheckUpdatePlugin");
        this.availablePlugins.add("cr.libre.firmador.plugins.DummyPlugin");
        this.availablePlugins.add("cr.libre.firmador.plugins.CheckUpdatePlugin");
    }

    public String getDefaultSignMessage() {
        return this.defaultSignMessage;
    }

    public SignatureLevel getCAdESLevel() {
        SignatureLevel level = SignatureLevel.CAdES_BASELINE_LTA;
        switch (this.cAdESLevel) {
            case "T":
                level = SignatureLevel.CAdES_BASELINE_T;
                break;
            case "LT":
                level = SignatureLevel.CAdES_BASELINE_LT;
                break;
            case "LTA":
                level = SignatureLevel.CAdES_BASELINE_LTA;
                break;
            default:
                level = SignatureLevel.CAdES_BASELINE_LTA;
        }

        return level;
    }

    public SignatureLevel getPAdESLevel() {
        SignatureLevel level = SignatureLevel.PAdES_BASELINE_LTA;
        switch (this.pAdESLevel) {
            case "T":
                level = SignatureLevel.PAdES_BASELINE_T;
                break;
            case "LT":
                level = SignatureLevel.PAdES_BASELINE_LT;
                break;
            case "LTA":
                level = SignatureLevel.PAdES_BASELINE_LTA;
                break;
            default:
                level = SignatureLevel.PAdES_BASELINE_LTA;
        }

        return level;
    }

    public SignatureLevel getXAdESLevel() {
        SignatureLevel level = SignatureLevel.XAdES_BASELINE_LTA;
        switch (this.xAdESLevel) {
            case "T":
                level = SignatureLevel.XAdES_BASELINE_T;
                break;
            case "LT":
                level = SignatureLevel.XAdES_BASELINE_LT;
                break;
            case "LTA":
                level = SignatureLevel.XAdES_BASELINE_LTA;
                break;
            default:
                level = SignatureLevel.XAdES_BASELINE_LTA;
        }

        return level;
    }

    public void addListener(ConfigListener toAdd) {
        this.listeners.add(toAdd);
    }

    public String getDateFormat() {
        try {
            return this.dateFormat;
        } catch (Exception e) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, (String) null, "Error retornando dateFormat: " + e);
            e.printStackTrace();
            return "dd/MM/yyyy hh:mm:ss a";
        }
    }

    public String getImage() {
        if (this.image == null) {
            return null;
        } else {
            File temp = new File(this.image);
            boolean exists = temp.exists();
            return exists ? temp.toURI().toString() : null;
        }
    }

    public String getVersion() {
        String versionStr = this.getClass().getPackage().getImplementationVersion();
        if (versionStr == null) {
            versionStr = this.defaultDevelopmentVersion;
        }

        return versionStr;
    }

    /**
     * Colores para firmas visibles
     **/
    public String getFontName(String fontName, boolean isPdf) {
        String selectedFontName = "";
        switch (fontName) {
            case "Arial Regular":
            case "Arial Italic":
            case "Arial Bold":
            case "Arial Bold Italic":
                if (!isPdf) {
                    selectedFontName = "Arial";
                } else {
                    selectedFontName = "SansSerif";
                }
                break;
            case "Helvetica Regular":
            case "Helvetica Oblique":
            case "Helvetica Bold":
            case "Helvetica Bold Oblique":
                if (!isPdf) {
                    selectedFontName = "Helvetica";
                } else {
                    selectedFontName = "SansSerif";
                }
                break;
            case "Nimbus Sans Regular":
            case "Nimbus Sans Italic":
            case "Nimbus Sans Bold":
            case "Nimbus Sans Bold Italic":
                if (!isPdf) {
                    selectedFontName = "Nimbus Sans";
                } else {
                    selectedFontName = "SansSerif";
                }
                break;
            case "Nimbus Roman Regular":
            case "Nimbus Roman Italic":
            case "Nimbus Roman Bold":
            case "Nimbus Roman Bold Italic":
                if (!isPdf) {
                    selectedFontName = "Nimbus Roman";
                } else {
                    selectedFontName = "Serif";
                }
                break;
            case "Times New Roman Regular":
            case "Times New Roman Italic":
            case "Times New Roman Bold":
            case "Times New Roman Bold Italic":
                if (!isPdf) {
                    selectedFontName = "Times New Roman";
                } else {
                    selectedFontName = "Serif";
                }
                break;
            case "Courier New Regular":
            case "Courier New Italic":
            case "Courier New Bold":
            case "Courier New Bold Italic":
                if (!isPdf) {
                    selectedFontName = "Courier New";
                } else {
                    selectedFontName = "Monospaced";
                }
                break;
            case "Nimbus Mono PS Regular":
            case "Nimbus Mono PS Italic":
            case "Nimbus Mono PS Bold":
            case "Nimbus Mono PS Bold Italic":
                if (!isPdf) {
                    selectedFontName = "Nimbus Mono PS";
                } else {
                    selectedFontName = "Monospaced";
                }
                break;
            default:
                selectedFontName = "SansSerif";
        }

        return selectedFontName;
    }

    public int getFontStyle(String fontName) {
        switch (fontName) {
            case "Arial Regular":
            case "Courier New Regular":
            case "Helvetica Regular":
            case "Nimbus Roman Regular":
            case "Nimbus Sans Regular":
            case "Nimbus Mono PS Regular":
            case "Times New Roman Regular":
                return 0;
            case "Arial Italic":
            case "Courier New Italic":
            case "Helvetica Oblique":
            case "Nimbus Roman Italic":
            case "Nimbus Sans Italic":
            case "Nimbus Mono PS Italic":
            case "Times New Roman Italic":
                return 2;
            case "Arial Bold":
            case "Courier New Bold":
            case "Helvetica Bold":
            case "Nimbus Roman Bold":
            case "Nimbus Sans Bold":
            case "Nimbus Mono PS Bold":
            case "Times New Roman Bold":
                return 1;
            case "Arial Bold Italic":
            case "Courier New Bold Italic":
            case "Helvetica Bold Oblique":
            case "Nimbus Roman Bold Italic":
            case "Nimbus Sans Bold Italic":
            case "Nimbus Mono PS Bold Italic":
            case "Times New Roman Bold Italic":
                return 3;
            default:
                return 0;
        }
    }

    public SignerTextPosition getFontAlignment() {
        SignerTextPosition position = SignerTextPosition.RIGHT;
        switch (this.fontAlignment) {
            case "RIGHT":
                position = SignerTextPosition.RIGHT;
                break;
            case "LEFT":
                position = SignerTextPosition.LEFT;
                break;
            case "BOTTOM":
                position = SignerTextPosition.BOTTOM;
                break;
            case "TOP":
                position = SignerTextPosition.TOP;
        }

        return position;
    }

    public Color getFontColor() {
        if (this.fontColor.equalsIgnoreCase("transparente")) {
            return new Color(255, 255, 255, 0);
        } else {
            try {
                return Color.decode(this.fontColor);
            } catch (Exception e) {
                Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, (String) null, "Error decodificando fontColor:" + e);
                e.printStackTrace();
                return new Color(0, 0, 0, 255);
            }
        }
    }

    public Color getBackgroundColor() {
        if (this.backgroundColor.equalsIgnoreCase("transparente")) {
            return new Color(255, 255, 255, 0);
        } else {
            try {
                return Color.decode(this.backgroundColor);
            } catch (Exception e) {
                Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, (String) null, "Error decodificando backgroundColor: " + e);
                e.printStackTrace();
                return new Color(255, 255, 255, 0);
            }
        }
    }

}
