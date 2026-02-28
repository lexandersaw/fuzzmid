package burp.prompt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PromptCategory {
    
    private String id;
    private String name;
    private String description;
    private int order;
    private List<PromptTemplate> templates;
    
    public PromptCategory() {
        this.templates = new ArrayList<>();
        this.order = 0;
    }
    
    public PromptCategory(String id, String name) {
        this.id = id;
        this.name = name;
        this.description = "";
        this.order = 0;
        this.templates = new ArrayList<>();
    }
    
    public PromptCategory(String id, String name, String description) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.order = 0;
        this.templates = new ArrayList<>();
    }
    
    public void addTemplate(PromptTemplate template) {
        if (template != null && !templates.contains(template)) {
            templates.add(template);
            template.setCategory(this.id);
        }
    }
    
    public void removeTemplate(String templateId) {
        templates.removeIf(t -> t.getId().equals(templateId));
    }
    
    public PromptTemplate getTemplate(String templateId) {
        for (PromptTemplate template : templates) {
            if (template.getId().equals(templateId)) {
                return template;
            }
        }
        return null;
    }
    
    public List<PromptTemplate> getTemplates() {
        return new ArrayList<>(templates);
    }
    
    public void setTemplates(List<PromptTemplate> templates) {
        this.templates = templates != null ? new ArrayList<>(templates) : new ArrayList<>();
        for (PromptTemplate template : this.templates) {
            template.setCategory(this.id);
        }
    }
    
    public int getTemplateCount() {
        return templates.size();
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
    
    public int getOrder() {
        return order;
    }
    
    public void setOrder(int order) {
        this.order = order;
    }
    
    @Override
    public String toString() {
        return "PromptCategory{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", templateCount=" + templates.size() +
                '}';
    }
}
