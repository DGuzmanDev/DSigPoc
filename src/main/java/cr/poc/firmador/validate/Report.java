package cr.poc.firmador.validate;

import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xml.utils.DSSXmlErrorListener;
import eu.europa.esig.dss.xml.utils.DomUtils;

import javax.xml.transform.Transformer;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;
import java.io.StringWriter;

public class Report {
    private StringWriter writer = new StringWriter();
    private String annotationChanges = new String();

    public Report(Reports reports) throws Exception {
        Transformer transformer = DomUtils.getSecureTransformerFactory().newTemplates(new StreamSource(this.getClass().getResourceAsStream("/xslt/html/simple-report.xslt"))).newTransformer();
        transformer.setErrorListener(new DSSXmlErrorListener());
        transformer.transform(new StreamSource(new StringReader(reports.getXmlSimpleReport())), new StreamResult(this.writer));

        for (SignatureWrapper wrapper : reports.getDiagnosticData().getSignatures()) {
            if (!wrapper.getPdfAnnotationChanges().isEmpty()) {
                this.annotationChanges = "<p><b>Aviso importante:</b> el siguiente documento firmado tiene modificaciones (anotaciones) añadidas después de haberse firmado.</p>";
            }
        }

    }

    public String getReport() {
        return "<html>" + this.annotationChanges + this.writer.toString() + "</html>";
    }
}
