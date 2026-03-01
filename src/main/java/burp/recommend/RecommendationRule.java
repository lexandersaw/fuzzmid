package burp.recommend;

import java.util.regex.Pattern;

public class RecommendationRule {
    
    private final String id;
    private final String name;
    private final Pattern urlPattern;
    private final String description;
    private final String[] payloadTypes;
    private final int priority;
    
    public RecommendationRule(String id, Pattern urlPattern, String name,
                             String description, String[] payloadTypes, int priority) {
        this.id = id;
        this.name = name;
        this.urlPattern = urlPattern;
        this.description = description;
        this.payloadTypes = payloadTypes != null ? payloadTypes : new String[0];
        this.priority = priority;
    }
    
    public boolean matches(String url) {
        return urlPattern != null && urlPattern.matcher(url).find();
    }
    
    public String getId() { return id; }
    public String getName() { return name; }
    public Pattern getUrlPattern() { return urlPattern; }
    public String getDescription() { return description; }
    public String[] getPayloadTypes() { return payloadTypes; }
    public int getPriority() { return priority; }
}
