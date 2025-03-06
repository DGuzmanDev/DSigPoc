package cr.poc.firmador.utils;

import lombok.NoArgsConstructor;

import java.util.Objects;

@NoArgsConstructor
public class FirmadorUtils {
    public static Throwable getRootCause(Throwable throwable) {
        Objects.requireNonNull(throwable);

        Throwable rootCause;
        for (rootCause = throwable; rootCause.getCause() != null && rootCause.getCause() != rootCause; rootCause = rootCause.getCause()) {
        }

        return rootCause;
    }

}
