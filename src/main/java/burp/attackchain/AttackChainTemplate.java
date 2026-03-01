package burp.attackchain;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

public class AttackChainTemplate {
    
    public enum Difficulty {
        EASY, MEDIUM, HARD, EXPERT
    }
    
    public enum Impact {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    private String id;
    private String name;
    private String description;
    private List<ChainStep> steps;
    private String targetPattern;
    private List<String> requiredTags;
    private Difficulty difficulty;
    private Impact impact;
    private String author;
    private long createdAt;
    
    public AttackChainTemplate() {
        this.steps = new ArrayList<>();
        this.requiredTags = new ArrayList<>();
        this.difficulty = Difficulty.MEDIUM;
        this.impact = Impact.MEDIUM;
        this.createdAt = System.currentTimeMillis();
    }
    
    public AttackChainTemplate(String id, String name, String description) {
        this();
        this.id = id;
        this.name = name;
        this.description = description;
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public List<ChainStep> getSteps() {
        return new ArrayList<>(steps);
    }
    
    public void setSteps(List<ChainStep> steps) {
        this.steps = steps != null ? new ArrayList<>(steps) : new ArrayList<>();
    }
    
    public void addStep(ChainStep step) {
        if (step != null) {
            steps.add(step);
        }
    }
    
    public String getTargetPattern() {
        return targetPattern;
    }
    
    public void setTargetPattern(String targetPattern) {
        this.targetPattern = targetPattern;
    }
    
    public List<String> getRequiredTags() {
        return new ArrayList<>(requiredTags);
    }
    
    public void setRequiredTags(List<String> requiredTags) {
        this.requiredTags = requiredTags != null ? new ArrayList<>(requiredTags) : new ArrayList<>();
    }
    
    public void addRequiredTag(String tag) {
        if (tag != null && !tag.isEmpty() && !requiredTags.contains(tag)) {
            requiredTags.add(tag);
        }
    }
    
    public Difficulty getDifficulty() {
        return difficulty;
    }
    
    public void setDifficulty(Difficulty difficulty) {
        this.difficulty = difficulty;
    }
    
    public Impact getImpact() {
        return impact;
    }
    
    public void setImpact(Impact impact) {
        this.impact = impact;
    }
    
    public String getAuthor() {
        return author;
    }
    
    public void setAuthor(String author) {
        this.author = author;
    }
    
    public long getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }
    
    public boolean matchesPattern(String path) {
        if (targetPattern == null || targetPattern.isEmpty() || path == null) {
            return false;
        }
        
        String[] patterns = targetPattern.split("\\|");
        for (String pattern : patterns) {
            pattern = pattern.trim();
            if (pattern.contains(".*")) {
                if (path.matches(pattern)) {
                    return true;
                }
            } else if (path.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    public int getStepCount() {
        return steps.size();
    }
    
    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        json.put("id", id);
        json.put("name", name);
        json.put("description", description);
        json.put("targetPattern", targetPattern != null ? targetPattern : "");
        json.put("difficulty", difficulty.name());
        json.put("impact", impact.name());
        json.put("author", author != null ? author : "");
        json.put("createdAt", createdAt);
        
        JSONArray stepsArray = new JSONArray();
        for (ChainStep step : steps) {
            stepsArray.put(step.toJson());
        }
        json.put("steps", stepsArray);
        
        JSONArray tagsArray = new JSONArray();
        for (String tag : requiredTags) {
            tagsArray.put(tag);
        }
        json.put("requiredTags", tagsArray);
        
        return json;
    }
    
    public static AttackChainTemplate fromJson(JSONObject json) {
        if (json == null) return null;
        
        AttackChainTemplate template = new AttackChainTemplate();
        template.setId(json.optString("id", ""));
        template.setName(json.optString("name", ""));
        template.setDescription(json.optString("description", ""));
        template.setTargetPattern(json.optString("targetPattern", ""));
        template.setDifficulty(Difficulty.valueOf(json.optString("difficulty", "MEDIUM")));
        template.setImpact(Impact.valueOf(json.optString("impact", "MEDIUM")));
        template.setAuthor(json.optString("author", ""));
        template.setCreatedAt(json.optLong("createdAt", System.currentTimeMillis()));
        
        JSONArray stepsArray = json.optJSONArray("steps");
        if (stepsArray != null) {
            for (int i = 0; i < stepsArray.length(); i++) {
                ChainStep step = ChainStep.fromJson(stepsArray.getJSONObject(i));
                if (step != null) {
                    template.addStep(step);
                }
            }
        }
        
        JSONArray tagsArray = json.optJSONArray("requiredTags");
        if (tagsArray != null) {
            for (int i = 0; i < tagsArray.length(); i++) {
                template.addRequiredTag(tagsArray.optString(i, ""));
            }
        }
        
        return template;
    }
    
    @Override
    public String toString() {
        return String.format("AttackChainTemplate{id='%s', name='%s', steps=%d}", 
            id, name, steps.size());
    }
}
