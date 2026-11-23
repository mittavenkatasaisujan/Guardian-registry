package guardianregistry.client;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Retries and error handling against a stub server (the JDK's own HttpServer). */
class ClientTest {
    private HttpServer server;
    private final List<Long> sleeps = new ArrayList<>();
    private final List<String> bodies = new ArrayList<>();

    private GuardianRegistryClient start(int... statuses) throws IOException {
        AtomicInteger n = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            bodies.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            int i = n.getAndIncrement();
            int status = i < statuses.length ? statuses[i] : 200;
            String reply = status == 200
                ? "{\"check_id\":\"chk_1\",\"enrolled\":true,\"status\":\"allowed\",\"may_execute\":true,\"reasons\":[]}"
                : "{\"detail\":\"status " + status + "\"}";
            if (status == 429) ex.getResponseHeaders().add("Retry-After", "2");
            byte[] b = reply.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.start();
        return GuardianRegistryClient.builder("http://127.0.0.1:" + server.getAddress().getPort(), "key")
            .sleeper(sleeps::add).build();
    }

    @AfterEach void stop() { if (server != null) server.stop(0); }

    @Test void retriesTheSameRequestOnBusyAndRateLimit() throws IOException {
        GuardianRegistryClient gr = start(503, 429, 200);
        CheckResult r = gr.check("+919800000001", "TXN-9", 50_000L, "shop@upi", "upi");
        assertTrue(r.mayExecute());
        assertEquals("chk_1", r.checkId());
        assertEquals(3, bodies.size());
        assertEquals(bodies.get(0), bodies.get(2));            // the identical, idempotent request
        assertEquals("TXN-9", new JSONObject(bodies.get(0)).getString("participant_txn_id"));
        assertTrue(sleeps.get(1) >= 2000);                     // Retry-After honoured
    }

    @Test void clientErrorsAreThrownAtOnce() throws IOException {
        GuardianRegistryClient gr = start(400);
        GuardianRegistryException e = assertThrows(GuardianRegistryException.class,
            () -> gr.check("+919800000001", "TXN-1", 100L, "x@upi", "upi"));
        assertEquals(400, e.status());
        assertEquals(1, bodies.size());
    }

    @Test void amountsArePaise() {
        GuardianRegistryClient gr = GuardianRegistryClient.builder("http://127.0.0.1:9", "k").build();
        assertThrows(IllegalArgumentException.class, () -> gr.check("+919800000001", "T", 0L, "x@upi", "upi"));
    }
}
