package guardianregistry.client;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/**
 * Against a real registry (CI starts one and sets these from scripts/bank_conformance.py --setup):
 * GR_LIVE_URL, GR_LIVE_API_KEY, GR_LIVE_MOBILE (a protected person), GR_LIVE_GUARDIAN_TOKEN.
 */
@EnabledIfEnvironmentVariable(named = "GR_LIVE_URL", matches = ".+")
class LiveRegistryTest {
    final String url = System.getenv("GR_LIVE_URL");
    final GuardianRegistryClient gr = GuardianRegistryClient.builder(url, System.getenv("GR_LIVE_API_KEY")).build();
    final String mobile = System.getenv("GR_LIVE_MOBILE");

    @Test void allowedPaymentAndOutcome() {
        CheckResult r = gr.check(mobile, "java-small-" + System.nanoTime(), 50_000L, "known@upi", "upi");
        assertTrue(r.mayExecute(), r.toString());
        assertNotNull(gr.reportOutcome(r.checkId(), true).raw().optString("completed_at", null));
        assertNotNull(gr.reportOutcome(r.checkId(), true).checkId());    // a retried report is fine
    }

    @Test void heldForTheGuardianThenApproved() throws Exception {
        CheckResult r = gr.check(mobile, "java-big-" + System.nanoTime(), 2_000_000L, "known@upi", "upi");
        assertTrue(r.waiting(), r.toString());
        assertFalse(r.mayExecute());
        HttpResponse<String> approve = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create(url + "/v1/guardian/payments/" + r.checkId() + "/approve"))
                .header("Authorization", "Bearer " + System.getenv("GR_LIVE_GUARDIAN_TOKEN"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(200, approve.statusCode(), approve.body());
        CheckResult done = gr.waitForDecision(r.checkId(), Duration.ofSeconds(10), Duration.ofMillis(200));
        assertEquals("approved", done.status());
        assertTrue(done.mayExecute());
    }

    @Test void notEnrolledPassesThrough() {
        CheckResult r = gr.check("+919000000000", "java-ne-" + System.nanoTime(), 10_000L, "x@upi", "upi");
        assertFalse(r.enrolled());
        assertTrue(r.mayExecute());
    }
}
