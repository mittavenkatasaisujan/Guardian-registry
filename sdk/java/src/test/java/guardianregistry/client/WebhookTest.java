package guardianregistry.client;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** The same vector as tests/test_sdk_python.py: both libraries and the server agree. */
class WebhookTest {
    static final String SECRET = "whsec_test_vector";
    static final byte[] BODY = "{\"id\":\"ntf_1\",\"event\":\"check.updated\",\"data\":{\"check\":{\"status\":\"approved\"}}}"
        .getBytes(StandardCharsets.UTF_8);
    static final String SIG = "sha256=a3ed14529afbe054881aa30a31cac823ef56a29687b30f5d0ba4860eecea0fa2";

    @Test void verifiesTheSharedVector() {
        assertTrue(GuardianRegistryClient.verifyWebhook(SECRET, BODY, SIG));
        assertEquals("check.updated", GuardianRegistryClient.parseWebhook(SECRET, BODY, SIG).getString("event"));
    }

    @Test void rejectsTamperingAndWrongSecrets() {
        byte[] tampered = (new String(BODY, StandardCharsets.UTF_8) + " ").getBytes(StandardCharsets.UTF_8);
        assertFalse(GuardianRegistryClient.verifyWebhook(SECRET, tampered, SIG));
        assertFalse(GuardianRegistryClient.verifyWebhook("other", BODY, SIG));
        assertFalse(GuardianRegistryClient.verifyWebhook(SECRET, BODY, null));
        assertFalse(GuardianRegistryClient.verifyWebhook(SECRET, BODY, "sha1=abc"));
        assertThrows(IllegalArgumentException.class, () -> GuardianRegistryClient.parseWebhook(SECRET, BODY, "sha256=00"));
    }
}
