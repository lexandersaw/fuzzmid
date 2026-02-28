package burp.fuzzing;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONObject;

public class FuzzingRule {
    
    private String id;
    private String name;
    private String description;
    private String category;
    private RuleCondition condition;
    private List<String> templates;
    private List<String> actions;
    private boolean enabled;
    
    public FuzzingRule() {
        this.templates = new ArrayList<>();
        this.actions = new ArrayList<>();
        this.enabled = true;
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
    
    public String getCategory() {
        return category;
    }
    
    public void setCategory(String category) {
        this.category = category;
    }
    
    public RuleCondition getCondition() {
        return condition;
    }
    
    public void setCondition(RuleCondition condition) {
        this.condition = condition;
    }
    
    public List<String> getTemplates() {
        return templates;
    }
    
    public void setTemplates(List<String> templates) {
        this.templates = templates != null ? new ArrayList<>(templates) : new ArrayList<>();
    }
    
    public void addTemplate(String template) {
        if (template != null && !templates.contains(template)) {
            templates.add(template);
        }
    }
    
    public List<String> getActions() {
        return actions;
    }
    
    public void setActions(List<String> actions) {
        this.actions = actions != null ? new ArrayList<>(actions) : new ArrayList<>();
    }
    
    public void addAction(String action) {
        if (action != null && !actions.contains(action)) {
            actions.add(action);
        }
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        json.put("id", id);
        json.put("name", name);
        json.put("description", description);
        json.put("category", category);
        json.put("enabled", enabled);
        
        if (condition != null) {
            json.put("condition", condition.toJson());
        }
        
        JSONArray templatesArray = new JSONArray();
        for (String template : templates) {
            templatesArray.put(template);
        }
        json.put("templates", templatesArray);
        
        JSONArray actionsArray = new JSONArray();
        for (String action : actions) {
            actionsArray.put(action);
        }
        json.put("actions", actionsArray);
        
        return json;
    }
    
    public static FuzzingRule fromJson(JSONObject json) {
        FuzzingRule rule = new FuzzingRule();
        rule.setId(json.optString("id"));
        rule.setName(json.optString("name"));
        rule.setDescription(json.optString("description"));
        rule.setCategory(json.optString("category"));
        rule.setEnabled(json.optBoolean("enabled"));
        
        JSONObject condition = json.optJSONObject("condition");
        if (condition != null) {
            rule.setCondition(RuleCondition.fromJson(condition));
        }
        
        JSONArray templatesArray = json.optJSONArray("templates");
        if (templatesArray != null) {
            List<String> templates = new ArrayList<>();
            for (int i = 0; i < templatesArray.length(); i++) {
                templates.add(templatesArray.getString(i));
            }
            rule.setTemplates(templates);
        }
        
        JSONArray actionsArray = json.optJSONArray("actions");
        if (actionsArray != null) {
            List<String> actions = new ArrayList<>();
            for (int i = 0; i < actionsArray.length(); i++) {
                actions.add(actionsArray.getString(i));
            }
            rule.setActions(actions);
        }
        
        return rule;
    }
}
