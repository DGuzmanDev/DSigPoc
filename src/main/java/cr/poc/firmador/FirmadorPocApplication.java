package cr.poc.firmador;

import cr.poc.firmador.card.CardSignInfo;
import cr.poc.firmador.card.SmartCardManager;
import cr.poc.firmador.sign.FirmadorPAdES;
import cr.poc.firmador.sign.FirmadorOpenDocument;
import cr.poc.firmador.sign.FirmadorXAdES;
import cr.poc.firmador.sign.FirmadorCAdES;
import cr.poc.firmador.sign.FirmadorWord;
import cr.poc.firmador.utils.OfficeDocumentDebugger;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.util.StringUtils;

import java.io.File;
import java.security.KeyStore;
import java.util.List;
import java.util.Optional;

@SpringBootApplication
public class FirmadorPocApplication {

    private SmartCardManager smartCardManager;

    @Autowired
    public FirmadorPocApplication(SmartCardManager smartCardManager) {
        this.smartCardManager = smartCardManager;
    }

    public static void main(String[] args) {
        SpringApplication.run(FirmadorPocApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner() {
        return args -> {
            if (args.length < 1) {
                System.out.println("Usage: java -jar firmador.jar <command> <pin> [options]");
                System.out.println("Commands:");
                System.out.println("  list-cards    - List available smart cards");
                System.out.println("  sign-pdf      - Sign a PDF file");
                System.out.println("  sign-word     - Sign a Word document");
                System.out.println("  extract-word  - Extract Word document contents for debugging");
                System.out.println("    Options:");
                System.out.println("    --input     - Input file path");
                System.out.println("    --output    - Output signed file path");
                System.out.println("    --reason    - Signature reason");
                System.out.println("    --location  - Signature location");
                return;
            }

            String command = args[0];

            switch (command) {
                case "list-cards":
                    try {
                        listSmartCards(args);
                    } catch (Throwable e) {
                        throw new RuntimeException(e);
                    }
                    break;
                case "sign-pdf":
                    if (args.length < 5) {
                        System.out.println("Missing required arguments for sign-pdf");
                        return;
                    }
                    handleSignPdf(args);
                    break;
                case "sign-word":
                    if (args.length < 5) {
                        System.out.println("Missing required arguments for sign-word");
                        return;
                    }
                    handleSignWord(args);
                    break;
                case "extract-word":
                    if (args.length < 3) {
                        System.out.println("Usage: extract-word --input <word-file>");
                        return;
                    }
                    handleExtractWord(args);
                    break;
                default:
                    System.out.println("Unknown command: " + command);
            }
        };
    }

    private void listSmartCards(String... args) throws Throwable {
        try {
            // Create detector with PIN
            String pin = args.length > 1 ? args[1] : null;
            Optional<KeyStore.PasswordProtection> keyStorePasswordProtection = Optional.empty();

            if (StringUtils.hasText(pin)) {
                keyStorePasswordProtection = Optional.of(new KeyStore.PasswordProtection(pin.toCharArray()));
            }


            // Get available cards
            List<CardSignInfo> cards = smartCardManager.readCertificatesInfo(keyStorePasswordProtection);

            if (cards.isEmpty()) {
                System.out.println("No smart cards detected");
                return;
            }

            System.out.println("Detected smart cards:");
            for (CardSignInfo card : cards) {
                System.out.println("- Name: " + card.getCommonName());
                System.out.println("  ID: " + card.getIdentification());
                System.out.println("  Organization: " + card.getOrganization());
                System.out.println("  Expires: " + card.getExpires());
                System.out.println();
            }
        } catch (Throwable e) {
            System.err.println("Error detecting smart cards: " + e.getMessage());
        }
    }

    private void handleSignPdf(String[] args) {
        // Get PIN from second argument
        String pin = args[1];
        if (pin == null || pin.isEmpty()) {
            System.out.println("PIN is required as second argument");
            return;
        }

        String inputPath = null;
        String outputPath = null;
        String reason = null;
        String location = null;

        // Parse arguments
        for (int i = 2; i < args.length; i += 2) {
            if (i + 1 >= args.length) break;

            switch (args[i]) {
                case "--input":
                    inputPath = args[i + 1];
                    break;
                case "--output":
                    outputPath = args[i + 1];
                    break;
                case "--reason":
                    reason = args[i + 1];
                    break;
                case "--location":
                    location = args[i + 1];
                    break;
            }
        }

        // Validate required arguments
        if (inputPath == null || outputPath == null) {
            System.out.println("Missing required input/output paths");
            return;
        }

        try {
            // Get available cards
            List<CardSignInfo> cards = smartCardManager.readCertificatesInfo(Optional.of(new KeyStore.PasswordProtection(pin.toCharArray())));

            if (cards.isEmpty()) {
                System.out.println("No smart cards detected");
                return;
            }

            // Use the first available card
            CardSignInfo card = cards.get(0);

            // Create PDF signer
            FirmadorPAdES signer = new FirmadorPAdES();

            // Sign document
            File inputFile = new File(inputPath);
            DSSDocument toSignDocument = new FileDocument(inputFile);
            DSSDocument signedDocument = signer.sign(toSignDocument, card, reason, location, null, null, false);

            // Save signed document
            File outputFile = new File(outputPath);
            signedDocument.save(outputPath);

            System.out.println("Document signed successfully");
            System.out.println("Output: " + outputFile.getAbsolutePath());

        } catch (Throwable e) {
            System.err.println("Error signing document: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleSignWord(String[] args) {
        try (FirmadorWord signer = new FirmadorWord()) {
            // Get PIN from second argument
            String pin = args[1];
            if (pin == null || pin.isEmpty()) {
                System.out.println("PIN is required as second argument");
                return;
            }

            String inputPath = null;
            String outputPath = null;

            // Parse arguments
            for (int i = 2; i < args.length; i += 2) {
                if (i + 1 >= args.length) break;

                switch (args[i]) {
                    case "--input":
                        inputPath = args[i + 1];
                        break;
                    case "--output":
                        outputPath = args[i + 1];
                        break;
                }
            }

            // Validate required arguments
            if (inputPath == null || outputPath == null) {
                System.out.println("Missing required input/output paths");
                return;
            }

            try {
                // Validate input file exists
                File inputFile = new File(inputPath);
                if (!inputFile.exists()) {
                    System.err.println("Input file does not exist: " + inputPath);
                    return;
                }

                // Create output directory if it doesn't exist
                File outputFile = new File(outputPath);
                File outputDir = outputFile.getParentFile();
                if (outputDir != null && !outputDir.exists()) {
                    outputDir.mkdirs();
                }

                // Get available cards
                List<CardSignInfo> cards = smartCardManager.readCertificatesInfo(Optional.of(new KeyStore.PasswordProtection(pin.toCharArray())));

                if (cards.isEmpty()) {
                    System.out.println("No smart cards detected");
                    return;
                }

                // Use the first available card
                CardSignInfo card = cards.get(0);

                // Sign document
                DSSDocument toSignDocument = new FileDocument(inputFile);
                DSSDocument signedDocument = signer.sign(toSignDocument, card);

                if (signedDocument == null) {
                    System.err.println("Failed to sign document");
                    return;
                }

                // Save signed document
                signedDocument.save(outputPath);
                System.out.println("Document signed successfully");
                System.out.println("Output: " + outputFile.getAbsolutePath());

            } catch (Throwable e) {
                System.err.println("Error signing document: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private void handleExtractWord(String[] args) {
        String inputPath = null;

        // Parse arguments
        for (int i = 1; i < args.length; i += 2) {
            if (i + 1 >= args.length) break;

            if ("--input".equals(args[i])) {
                inputPath = args[i + 1];
            }
        }

        // Validate required arguments
        if (inputPath == null) {
            System.out.println("Missing required input path");
            return;
        }

        try {
            // Validate input file exists
            File inputFile = new File(inputPath);
            if (!inputFile.exists()) {
                System.err.println("Input file does not exist: " + inputPath);
                return;
            }

            try (FirmadorWord extractor = new FirmadorWord()) {
                String debugDirName = OfficeDocumentDebugger.extractAndLogContents(inputFile, "extracted");
                System.out.println("Word document contents extracted to: " + debugDirName);
            }

        } catch (Throwable e) {
            System.err.println("Error extracting Word document: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
