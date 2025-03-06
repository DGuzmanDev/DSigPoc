package cr.poc.firmador.exception;

public class UnsupportedArchitectureException extends Exception {
    public UnsupportedArchitectureException(String errorMessage, Throwable exception) {
        super(errorMessage, exception);
    }
}
