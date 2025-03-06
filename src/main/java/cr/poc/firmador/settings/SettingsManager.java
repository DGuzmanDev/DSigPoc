package cr.poc.firmador.settings;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SettingsManager {
    private static SettingsManager cm = new SettingsManager();
    private Path path = null;
    private Properties props = new Properties();
    private Settings settings = null;

    public static SettingsManager getInstance() {
        return cm;
    }

    public String getProperty(String key) {
        return this.props.getProperty(key, "");
    }

    public void setProperty(String key, String value) {
        this.props.setProperty(key, value);
    }

    public boolean loadConfig() {
        boolean loaded = false;

        try {
            File configFile = new File(this.getConfigFile());
            if (configFile.exists()) {
                InputStream inputStream = new FileInputStream(configFile);
                Reader reader = new InputStreamReader(inputStream, "UTF-8");
                this.props.load(reader);
                reader.close();
                inputStream.close();
                loaded = true;
            }
        } catch (IOException ex) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, (String) null, ex);
            ex.printStackTrace();
        }

        return loaded;
    }

    public Settings getSettings() {
        Settings conf = new Settings();
        boolean loaded = this.loadConfig();
        if (loaded) {
            conf.withoutVisibleSign = Boolean.parseBoolean(this.props.getProperty("withoutvisiblesign", String.valueOf(conf.withoutVisibleSign)));
            conf.showLogs = Boolean.parseBoolean(this.props.getProperty("showlogs", String.valueOf(conf.showLogs)));
            conf.overwriteSourceFile = Boolean.parseBoolean(this.props.getProperty("overwritesourcefile", String.valueOf(conf.overwriteSourceFile)));
            conf.reason = this.props.getProperty("reason", conf.reason);
            conf.place = this.props.getProperty("place", conf.place);
            conf.contact = this.props.getProperty("contact", conf.contact);
            conf.dateFormat = this.props.getProperty("dateformat", conf.dateFormat);
            conf.defaultSignMessage = this.props.getProperty("defaultsignmessage", conf.defaultSignMessage);
            conf.pageNumber = Integer.parseInt(this.props.getProperty("pagenumber", conf.pageNumber.toString()));
            conf.signWidth = Integer.parseInt(this.props.getProperty("signwidth", conf.signWidth.toString()));
            conf.signHeight = Integer.parseInt(this.props.getProperty("signheight", conf.signHeight.toString()));
            conf.fontSize = Integer.parseInt(this.props.getProperty("fontsize", conf.fontSize.toString()));
            conf.font = this.props.getProperty("font", conf.font);
            conf.fontColor = this.props.getProperty("fontcolor", conf.fontColor);
            conf.backgroundColor = this.props.getProperty("backgroundcolor", conf.backgroundColor);
            conf.signX = Integer.parseInt(this.props.getProperty("singx", conf.signX.toString()));
            conf.signY = Integer.parseInt(this.props.getProperty("singy", conf.signY.toString()));
            conf.image = this.props.getProperty("image");
            conf.fontAlignment = this.props.getProperty("fontalignment", conf.fontAlignment);
            conf.portNumber = Integer.parseInt(this.props.getProperty("portnumber", conf.portNumber.toString()));
            conf.pAdESLevel = this.props.getProperty("padesLevel", conf.pAdESLevel);
            conf.xAdESLevel = this.props.getProperty("xadesLevel", conf.xAdESLevel);
            conf.cAdESLevel = this.props.getProperty("cadesLevel", conf.cAdESLevel);
            conf.extraPKCS11Lib = this.props.getProperty("extrapkcs11Lib");
            conf.pKCS12File = this.getListFromString(this.props.getProperty("pkcs12file", ""), conf.pKCS12File);
            conf.activePlugins = this.getListFromString(this.props.getProperty("plugins", ""), conf.activePlugins);
            conf.pDFImgScaleFactor = this.getFloatFromString(this.props.getProperty("pdfimgscalefactor", String.format("%.2f", conf.pDFImgScaleFactor)));
        }

        return conf;
    }

    public Settings getAndCreateSettings() {
        if (this.settings != null) {
            return this.settings;
        } else {
            Settings dev = new Settings();

            try {
                if (this.path != null && !Files.exists(this.path, new LinkOption[0])) {
                    Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, (String) null, "Config File does not exist");
                    return dev;
                }

                dev = this.getSettings();
            } catch (Exception e) {
                Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, (String) null, e);
                e.printStackTrace();
                this.setSettings(dev, true);
            }

            this.settings = dev;
            return dev;
        }
    }

    public void setSettings(Settings conf, boolean save) {
        this.setProperty("withoutvisiblesign", String.valueOf(conf.withoutVisibleSign));
        this.setProperty("overwritesourcefile", String.valueOf(conf.overwriteSourceFile));
        this.setProperty("reason", conf.reason);
        this.setProperty("place", conf.place);
        this.setProperty("contact", conf.contact);
        this.setProperty("dateformat", conf.dateFormat);
        this.setProperty("defaultsignmessage", conf.defaultSignMessage);
        this.setProperty("pagenumber", conf.pageNumber.toString());
        this.setProperty("signwidth", conf.signWidth.toString());
        this.setProperty("signheight", conf.signHeight.toString());
        this.setProperty("fontsize", conf.fontSize.toString());
        this.setProperty("font", conf.font);
        this.setProperty("fontcolor", conf.fontColor);
        this.setProperty("backgroundcolor", conf.backgroundColor);
        this.setProperty("singx", conf.signX.toString());
        this.setProperty("singy", conf.signY.toString());
        this.setProperty("fontalignment", conf.fontAlignment.toString());
        this.setProperty("portnumber", conf.portNumber.toString());
        this.setProperty("showlogs", String.valueOf(conf.showLogs));
        this.setProperty("pdfimgscalefactor", String.format("%.2f", conf.pDFImgScaleFactor));
        this.setProperty("padesLevel", conf.pAdESLevel);
        this.setProperty("xadesLevel", conf.xAdESLevel);
        this.setProperty("cadesLevel", conf.cAdESLevel);
        this.setProperty("plugins", this.getListRepr(conf.activePlugins));
        if (conf.extraPKCS11Lib != null && conf.extraPKCS11Lib != "") {
            this.setProperty("extrapkcs11Lib", conf.extraPKCS11Lib);
        } else if (this.props.get("extrapkcs11Lib") != null) {
            this.props.remove("extrapkcs11Lib");
        }

        this.setProperty("pkcs12file", this.getListRepr(conf.pKCS12File));
        if (conf.image != null) {
            this.setProperty("image", conf.image);
        } else if (this.props.get("image") != null) {
            this.props.remove("image");
        }

        if (save) {
            this.saveConfig();
        }
    }

    private String getListRepr(List<String> items) {
        return String.join("|", items);
    }

    public Path getConfigDir() throws IOException {
        String osName = System.getProperty("os.name").toLowerCase();
        String homepath = System.getProperty("user.home");
        String suffixpath = ".config/firmadorlibre";
        if (osName.contains("windows")) {
            homepath = System.getenv("APPDATA");
            suffixpath = "firmadorlibre";
        }

        this.path = FileSystems.getDefault().getPath(homepath, suffixpath);
        if (!Files.isDirectory(this.path, new LinkOption[0])) {
            Files.createDirectories(this.path);
            if (osName.contains("windows")) {
                Files.setAttribute(this.path, "dos:hidden", true);
            }
        }

        return this.path;
    }

    public Path getPathConfigFile(String name) throws IOException {
        if (this.path == null) {
            this.path = this.getConfigDir();
            this.path = this.path.getFileSystem().getPath(this.path.toString(), name);
        }

        return this.path;
    }

    public String getConfigFile(String name) throws IOException {
        return this.getPathConfigFile(name).toString();
    }

    public void saveConfig() {
        OutputStreamWriter writer = null;

        try {
            writer = new OutputStreamWriter(new FileOutputStream(this.getConfigFile()), StandardCharsets.UTF_8);
            this.props.store(writer, "Firmador Libre settings");
        } catch (IOException ex) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, (String) null, ex);
            ex.printStackTrace();
        } finally {
            try {
                if (writer != null) {
                    writer.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, (String) null, ex);
                ex.printStackTrace();
            }
        }
    }

    private String getConfigFile() throws IOException {
        return this.path == null ? this.getConfigFile("config.properties") : this.path.toString();
    }

    private List<String> getListFromString(String data, List<String> defaultdata) {
        if (data.isEmpty() && defaultdata != null && !defaultdata.isEmpty()) {
            return defaultdata;
        } else {
            List<String> plugins = new ArrayList<>();

            for (String item : data.split("\\|")) {
                if (!item.isEmpty()) {
                    plugins.add(item);
                }
            }

            return plugins;
        }
    }

    private float getFloatFromString(String value) {
        String valueTmp = value.replace(",", ".");
        float fValue = 1.0F;

        try {
            fValue = Float.parseFloat(valueTmp);
        } catch (Exception e) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, (String) null, e);
            e.printStackTrace();
            fValue = 1.0F;
        }

        return fValue;
    }
}
