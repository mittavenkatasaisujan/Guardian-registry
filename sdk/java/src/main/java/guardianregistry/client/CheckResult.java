package guardianregistry.client;

import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/** A payment check as the registry sees it. {@link #raw()} has every field. */
public final class CheckResult {
    private final JSONObject raw;

    CheckResult(JSONObject raw) { this.raw = raw; }

    public JSONObject raw() { return raw; }

    /** Null when the customer isn't enrolled. */
    public String checkId() { return raw.optString("check_id", null); }

    public boolean enrolled() { return raw.optBoolean("enrolled", true); }

    public String status() { return raw.optString("status", enrolled() ? "" : "allowed"); }

    /** True: you may move the money now. Only this decides that. */
    public boolean mayExecute() { return raw.optBoolean("may_execute", false); }

    /** Held for a guardian or cooling off: don't move money yet, don't fail it either. */
    public boolean waiting() { return "cooling_off".equals(status()) || "pending_approval".equals(status()); }

    public List<String> reasons() {
        List<String> out = new ArrayList<>();
        JSONArray a = raw.optJSONArray("reasons");
        if (a != null) for (int i = 0; i < a.length(); i++) out.add(a.getString(i));
        return out;
    }

    @Override public String toString() { return "CheckResult" + raw; }
}
