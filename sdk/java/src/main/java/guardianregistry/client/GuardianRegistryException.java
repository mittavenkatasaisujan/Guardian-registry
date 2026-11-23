package guardianregistry.client;

/** An error answer from the registry (status 0: the request never got an answer). */
public final class GuardianRegistryException extends RuntimeException {
    private final int status;
    private final String detail;

    public GuardianRegistryException(int status, String detail) {
        super("HTTP " + status + ": " + detail);
        this.status = status;
        this.detail = detail;
    }

    public int status() { return status; }

    public String detail() { return detail; }
}
