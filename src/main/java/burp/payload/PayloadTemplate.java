package burp.payload;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

public class PayloadTemplate {
    
    private String id;
    private String name;
    private String template;
    private String category;
    private List<String> tags;
    private int priority;
    private String description;
    private Map<String, String> defaultVariables;
    private String author;
    private long createdAt;
    private long updatedAt;
    private boolean isCustom;
    
    public PayloadTemplate() {
        this.tags = new ArrayList<>();
        this.defaultVariables = new HashMap<>();
        this.priority = 5;
        this.isCustom = false;
        this.createdAt = System.currentTimeMillis();
        this.updatedAt = this.createdAt;
    }
    
    public PayloadTemplate(String id, String name, String template, String category, String tag, int priority) {
        this();
        this.id = id;
        this.name = name;
        this.template = template;
        this.category = category;
        if (tag != null && !tag.isEmpty()) {
            this.tags.add(tag);
        }
        this.priority = priority;
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
    
    public String getTemplate() {
        return template;
    }
    
    public void setTemplate(String template) {
        this.template = template;
        this.updatedAt = System.currentTimeMillis();
    }
    
    public String getCategory() {
        return category;
    }
    
    public void setCategory(String category) {
        this.category = category;
    }
    
    public List<String> getTags() {
        return new ArrayList<>(tags);
    }
    
    public void setTags(List<String> tags) {
        this.tags = tags != null ? new ArrayList<>(tags) : new ArrayList<>();
    }
    
    public void addTag(String tag) {
        if (tag != null && !tag.isEmpty() && !tags.contains(tag)) {
            tags.add(tag);
        }
    }
    
    public void removeTag(String tag) {
        tags.remove(tag);
    }
    
    public int getPriority() {
        return priority;
    }
    
    public void setPriority(int priority) {
        this.priority = Math.max(1, Math.min(10, priority));
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public Map<String, String> getDefaultVariables() {
        return new HashMap<>(defaultVariables);
    }
    
    public void setDefaultVariables(Map<String, String> defaultVariables) {
        this.defaultVariables = defaultVariables != null ? new HashMap<>(defaultVariables) : new HashMap<>();
    }
    
    public PayloadTemplate addVariable(String name, String value) {
        this.defaultVariables.put(name, value);
        return this;
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
    
    public long getUpdatedAt() {
        return updatedAt;
    }
    
    public void setUpdatedAt(long updatedAt) {
        this.updatedAt = updatedAt;
    }
    
    public boolean isCustom() {
        return isCustom;
    }
    
    public void setCustom(boolean custom) {
        isCustom = custom;
    }
    
    public String getFormattedCreatedAt() {
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm").format(new java.util.Date(createdAt));
    }
    
    public String getFormattedUpdatedAt() {
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm").format(new java.util.Date(updatedAt));
    }
    
    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        json.put("id", id);
        json.put("name", name);
        json.put("template", template);
        json.put("category", category);
        json.put("priority", priority);
        json.put("description", description != null ? description : "");
        json.put("author", author != null ? author : "");
        json.put("createdAt", createdAt);
        json.put("updatedAt", updatedAt);
        json.put("isCustom", isCustom);
        
        JSONArray tagsArray = new JSONArray();
        for (String tag : tags) {
            tagsArray.put(tag);
        }
        json.put("tags", tagsArray);
        
        JSONObject varsObj = new JSONObject();
        for (Map.Entry<String, String> entry : defaultVariables.entrySet()) {
            varsObj.put(entry.getKey(), entry.getValue());
        }
        json.put("defaultVariables", varsObj);
        
        return json;
    }
    
    public static PayloadTemplate fromJson(JSONObject json) {
        if (json == null) return null;
        
        PayloadTemplate template = new PayloadTemplate();
        template.setId(json.optString("id", ""));
        template.setName(json.optString("name", ""));
        template.setTemplate(json.optString("template", ""));
        template.setCategory(json.optString("category", "Custom"));
        template.setPriority(json.optInt("priority", 5));
        template.setDescription(json.optString("description", ""));
        template.setAuthor(json.optString("author", ""));
        template.setCreatedAt(json.optLong("createdAt", System.currentTimeMillis()));
        template.setUpdatedAt(json.optLong("updatedAt", System.currentTimeMillis()));
        template.setCustom(json.optBoolean("isCustom", true));
        
        JSONArray tagsArray = json.optJSONArray("tags");
        if (tagsArray != null) {
            for (int i = 0; i < tagsArray.length(); i++) {
                template.addTag(tagsArray.optString(i, ""));
            }
        }
        
        JSONObject varsObj = json.optJSONObject("defaultVariables");
        if (varsObj != null) {
            for (String key : varsObj.keySet()) {
                template.addVariable(key, varsObj.optString(key, ""));
            }
        }
        
        return template;
    }
    
    @Override
    public String toString() {
        return String.format("PayloadTemplate{id='%s', name='%s', category='%s'}", id, name, category);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        PayloadTemplate that = (PayloadTemplate) obj;
        return id != null && id.equals(that.id);
    }
    
    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }
}
