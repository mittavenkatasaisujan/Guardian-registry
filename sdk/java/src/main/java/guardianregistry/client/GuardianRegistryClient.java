package guardianregistry.client;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import org.json.JSONObject;

/**
 * Client for banks and payment apps integrating with Guardian Registry (Java 17+).
 *
 * <pre>{@code
 * GuardianRegistryClient gr = GuardianRegistryClient.builder("https://registry.example.in", apiKey)
 *     .sslContext(mtlsContext)          // your client certificate; the registry pins it
 *     .build();
 * CheckResult r = gr.check("+919876543210", "TXN-123", 2_000_000L, "shop@upi", "upi");
 * if (r.mayExecute()) { ...move money...; gr.reportOutcome(r.checkId(), true); }
 * else if (r.waiting()) { ...tell the customer; wait for the signed webhook, or waitForDecision... }
 * }</pre>
 *
 * Retries are safe: a check is idempotent on your transaction id, so on a network error, 429
 * (Retry-After honoured) or 502/503/504 the same request is sent again. Other 4xx are thrown.
 * Amounts are long paise.
 */
public final class GuardianRegistryClient {
    public static final String VERSION = "0.22.0";
    private static final int[] RETRY = {429, 502, 503, 504};

    private final String base;
    private final String apiKey;
    private final HttpClient http;
    private final int retries;
    private final Sleeper sleeper;

    /** Lets tests skip real waiting. */
    @FunctionalInterface
    public interface Sleeper { void sleep(long millis) throws InterruptedException; }

    private GuardianRegistryClient(Builder b) {
        this.base = b.base.replaceAll("/+$", "");
        this.apiKey = b.apiKey;
        this.retries = b.retries;
        this.sleeper = b.sleeper;
        HttpClient.Builder hb = HttpClient.newBuilder().connectTimeout(b.timeout);
        if (b.sslContext != null) hb.sslContext(b.sslContext);
        this.http = hb.build();
    }

    public static Builder builder(String baseUrl, String apiKey) { return new Builder(baseUrl, apiKey); }

    public static final class Builder {
        private final String base;
        private final String apiKey;
        private SSLContext sslContext;
        private Duration timeout = Duration.ofSeconds(10);
        private int retries = 3;
        private Sleeper sleeper = Thread::sleep;

        private Builder(String base, String apiKey) { this.base = base; this.apiKey = apiKey; }
        public Builder sslContext(SSLContext c) { this.sslContext = c; return this; }
        public Builder timeout(Duration d) { this.timeout = d; return this; }
        public Builder retries(int n) { this.retries = n; return this; }
        public Builder sleeper(Sleeper s) { this.sleeper = s; return this; }
        public GuardianRegistryClient build() { return new GuardianRegistryClient(this); }
    }

    // ------------------------------------------------------------------ payments
    public CheckResult check(String mobile, String txnId, long amountPaise, String payee, String channel) {
        if (amountPaise <= 0) throw new IllegalArgumentException("amountPaise must be positive (paise, not rupees)");
        JSONObject body = new JSONObject().put("mobile", mobile).put("participant_txn_id", txnId)
            .put("amount", amountPaise).put("payee", payee).put("channel", channel == null ? "upi" : channel);
        return new CheckResult(call("POST", "/v1/checks", body, true));
    }

    public CheckResult getCheck(String checkId) {
        return new CheckResult(call("GET", "/v1/checks/" + enc(checkId), null, true));
    }

    /** Poll until the check leaves cooling-off / pending approval, or the timeout passes. */
    public CheckResult waitForDecision(String checkId, Duration timeout, Duration pollEvery) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            CheckResult r = getCheck(checkId);
            if (!r.waiting() || System.nanoTime() >= deadline) return r;
            pause(pollEvery.toMillis());
        }
    }

    public CheckResult reportOutcome(String checkId, boolean completed) {
        try {
            return new CheckResult(call("POST", "/v1/checks/" + enc(checkId) + "/outcome",
                new JSONObject().put("completed", completed), true));
        } catch (GuardianRegistryException e) {
            if (e.status() == 409 && e.detail().contains("already reported")) return getCheck(checkId);
            throw e;
        }
    }

    /** Once you know the outcome: confirmed fraud (true) or genuine (false). Tunes the scam signals. */
    public JSONObject labelFraud(String checkId, boolean fraud, String note) {
        return call("POST", "/v1/checks/" + enc(checkId) + "/fraud-label",
            new JSONObject().put("fraud", fraud).put("note", note == null ? JSONObject.NULL : note), true);
    }

    /** After you confirmed a fraud: protects every bank's customers from this payee. */
    public JSONObject reportFraudPayee(String payee, String reason, String caseRef) {
        return call("POST", "/v1/signals/fraud-payees", new JSONObject().put("payee", payee).put("reason", reason)
            .put("evidence_ref", caseRef == null ? JSONObject.NULL : caseRef), true);
    }

    public JSONObject payeeStatus(String payee) {
        return call("GET", "/v1/signals/fraud-payees/" + enc(payee), null, true);
    }

    // ------------------------------------------------------------------ webhooks
    /** X-GR-Signature = "sha256=" + hex HMAC-SHA256(secret, raw body). Constant-time compare. */
    public static boolean verifyWebhook(String secret, byte[] rawBody, String signature) {
        if (signature == null || !signature.startsWith("sha256=")) return false;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String expected = "sha256=" + HexFormat.of().formatHex(mac.doFinal(rawBody));
            return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                signature.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            return false;
        }
    }

    /** The verified event ({"id","event","created_at","data"}); de-duplicate on "id". */
    public static JSONObject parseWebhook(String secret, byte[] rawBody, String signature) {
        if (!verifyWebhook(secret, rawBody, signature)) throw new IllegalArgumentException("bad X-GR-Signature");
        return new JSONObject(new String(rawBody, StandardCharsets.UTF_8));
    }

    // ------------------------------------------------------------------ transport
    private JSONObject call(String method, String path, JSONObject body, boolean retry) {
        int attempts = retry ? retries + 1 : 1;
        for (int attempt = 0; ; attempt++) {
            HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(base + path))
                .timeout(Duration.ofSeconds(15))
                .header("X-Api-Key", apiKey).header("Accept", "application/json")
                .header("User-Agent", "guardian-registry-client-java/" + VERSION);
            if (body != null) {
                rb.header("Content-Type", "application/json")
                  .method(method, HttpRequest.BodyPublishers.ofString(body.toString()));
            } else {
                rb.method(method, HttpRequest.BodyPublishers.noBody());
            }
            HttpResponse<String> resp;
            try {
                resp = http.send(rb.build(), HttpResponse.BodyHandlers.ofString());
            } catch (IOException e) {
                if (attempt + 1 >= attempts) throw new GuardianRegistryException(0, "network error: " + e.getMessage());
                pause(backoff(attempt));
                continue;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new GuardianRegistryException(0, "interrupted");
            }
            int status = resp.statusCode();
            if (retryable(status) && attempt + 1 < attempts) {
                long wait = backoff(attempt);
                if (status == 429) {
                    Optional<String> ra = resp.headers().firstValue("Retry-After");
                    try { wait = Math.max(wait, (long) (Double.parseDouble(ra.orElse("1")) * 1000)); }
                    catch (NumberFormatException ignored) { /* keep the backoff */ }
                }
                pause(Math.min(wait, 30_000));
                continue;
            }
            String text = resp.body() == null ? "" : resp.body();
            JSONObject json = text.isBlank() ? new JSONObject() : new JSONObject(text);
            if (status >= 400) throw new GuardianRegistryException(status, json.optString("detail", "HTTP " + status));
            return json;
        }
    }

    private static boolean retryable(int status) {
        for (int s : RETRY) if (s == status) return true;
        return false;
    }

    private static long backoff(int attempt) { return Math.min(500L << attempt, 8_000L); }

    private void pause(long millis) {
        try { sleeper.sleep(millis); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("%40", "@"); }
}
