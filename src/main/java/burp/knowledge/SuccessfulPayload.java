package burp.knowledge;

import org.json.JSONObject;

public class SuccessfulPayload {
    
    private String id;
    private final String payload;
    private final String category;
    private final String vulnType;
    private final String targetDomain;
    private final String description;
    private final long timestamp;
    private final String responseIndicator;
    private final int severity;
    
    public SuccessfulPayload(String payload, String category, String vulnType,
                            String targetDomain, String description,
                            String responseIndicator, int severity) {
        this.payload = payload;
        this.category = category;
        this.vulnType = vulnType;
        this.targetDomain = targetDomain;
        this.description = description;
        this.timestamp = System.currentTimeMillis();
        this.responseIndicator = responseIndicator;
        this.severity = Math.max(1, Math.min(5, severity));
    }
    
    private SuccessfulPayload(String id, String payload, String category, String vulnType,
                             String targetDomain, String description, long timestamp,
                             String responseIndicator, int severity) {
        this.id = id;
        this.payload = payload;
        this.category = category;
        this.vulnType = vulnType;
        this.targetDomain = targetDomain;
        this.description = description;
        this.timestamp = timestamp;
        this.responseIndicator = responseIndicator;
        this.severity = severity;
    }
    
    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        json.put("id", id);
        json.put("payload", payload);
        json.put("category", category);
        json.put("vulnType", vulnType);
        json.put("targetDomain", targetDomain);
        json.put("description", description);
        json.put("timestamp", timestamp);
        json.put("responseIndicator", responseIndicator);
        json.put("severity", severity);
        return json;
    }
    
    public static SuccessfulPayload fromJson(JSONObject json) {
        if (json == null) return null;
        
        return new SuccessfulPayload(
            json.optString("id", null),
            json.optString("payload", null),
            json.optString("category", null),
            json.optString("vulnType", null),
            json.optString("targetDomain", null),
            json.optString("description", null),
            json.optLong("timestamp", System.currentTimeMillis()),
            json.optString("responseIndicator", null),
            json.optInt("severity", 3)
        );
    }
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getPayload() { return payload; }
    public String getCategory() { return category; }
    public String getVulnType() { return vulnType; }
    public String getTargetDomain() { return targetDomain; }
    public String getDescription() { return description; }
    public long getTimestamp() { return timestamp; }
    public String getResponseIndicator() { return responseIndicator; }
    public int getSeverity() { return severity; }
    
    public String getSeverityLabel() {
        switch (severity) {
            case 5: return "严重";
            case 4: return "高危";
            case 3: return "中危";
            case 2: return "低危";
            default: return "信息";
        }
    }
    
    @Override
    public String toString() {
        return String.format("SuccessfulPayload{id=%s, vulnType=%s, severity=%d}",
            id, vulnType, severity);
    }
}
