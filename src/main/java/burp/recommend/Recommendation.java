package burp.recommend;

import java.util.Arrays;
import java.util.List;

public class Recommendation {
    
    private final String name;
    private final String description;
    private final List<String> payloadTypes;
    private final int priority;
    private final String ruleId;
    
    public Recommendation(String name, String description, String[] payloadTypes,
                         int priority, String ruleId) {
        this.name = name;
        this.description = description;
        this.payloadTypes = Arrays.asList(payloadTypes);
        this.priority = priority;
        this.ruleId = ruleId;
    }
    
    public String getName() { return name; }
    public String getDescription() { return description; }
    public List<String> getPayloadTypes() { return payloadTypes; }
    public int getPriority() { return priority; }
    public String getRuleId() { return ruleId; }
    
    public String getPriorityLabel() {
        if (priority >= 9) return "高";
        if (priority >= 6) return "中";
        return "低";
    }
    
    @Override
    public String toString() {
        return String.format("Recommendation{name=%s, priority=%d, types=%s}",
            name, priority, payloadTypes);
    }
}
