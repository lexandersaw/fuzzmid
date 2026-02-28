package burp.prompt;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONObject;

public class PromptTemplateManager {
    
    private final String configDirPath;
    private final String templatesFilePath;
    private final Map<String, PromptTemplate> templates;
    private final Map<String, PromptCategory> categories;
    private final Map<String, String> promptNames;
    
    public PromptTemplateManager() {
        this.configDirPath = System.getProperty("user.home") + "/.config/fuzzMind";
        this.templatesFilePath = configDirPath + "/templates.json";
        this.templates = new LinkedHashMap<>();
        this.categories = new LinkedHashMap<>();
        this.promptNames = new LinkedHashMap<>();
        
        initializeDefaultCategories();
        loadTemplates();
    }
    
    private void initializeDefaultCategories() {
        addCategory(new PromptCategory("injection", "注入攻击"));
        addCategory(new PromptCategory("xss", "XSS攻击"));
        addCategory(new PromptCategory("file", "文件操作"));
        addCategory(new PromptCategory("auth", "认证破解"));
        addCategory(new PromptCategory("ssrf", "SSRF攻击"));
        addCategory(new PromptCategory("other", "其他"));
    }
    
    private void loadTemplates() {
        File templatesFile = new File(templatesFilePath);
        
        if (templatesFile.exists()) {
            try {
                String content = new String(Files.readAllBytes(Paths.get(templatesFilePath)), StandardCharsets.UTF_8);
                JSONObject json = new JSONObject(content);
                
                if (json.has("categories")) {
                    JSONArray categoriesArray = json.getJSONArray("categories");
                    for (int i = 0; i < categoriesArray.length(); i++) {
                        JSONObject catJson = categoriesArray.getJSONObject(i);
                        PromptCategory category = PromptCategory.fromJson(catJson);
                        if (category != null) {
                            categories.put(category.getId(), category);
                        }
                    }
                }
                
                if (json.has("templates")) {
                    JSONArray templatesArray = json.getJSONArray("templates");
                    for (int i = 0; i < templatesArray.length(); i++) {
                        JSONObject tplJson = templatesArray.getJSONObject(i);
                        PromptTemplate template = PromptTemplate.fromJson(tplJson);
                        if (template != null && template.isValid()) {
                            templates.put(template.getId(), template);
                            promptNames.put(template.getId(), template.getName());
                        }
                    }
                }
                
            } catch (Exception e) {
                System.err.println("Failed to load templates: " + e.getMessage());
            }
        }
    }
    
    public void saveTemplates() {
        try {
            File configDir = new File(configDirPath);
            if (!configDir.exists()) {
                configDir.mkdirs();
            }
            
            JSONObject json = new JSONObject();
            
            JSONArray categoriesArray = new JSONArray();
            List<PromptCategory> sortedCategories = new ArrayList<>(categories.values());
            sortedCategories.sort(Comparator.comparingInt(PromptCategory::getOrder));
            for (PromptCategory category : sortedCategories) {
                categoriesArray.put(category.toJson());
            }
            json.put("categories", categoriesArray);
            
            JSONArray templatesArray = new JSONArray();
            for (PromptTemplate template : templates.values()) {
                templatesArray.put(template.toJson());
            }
            json.put("templates", templatesArray);
            
            String jsonStr = json.toString(2);
            Files.write(Paths.get(templatesFilePath), jsonStr.getBytes(StandardCharsets.UTF_8));
            
        } catch (Exception e) {
            System.err.println("Failed to save templates: " + e.getMessage());
        }
    }
    
    public void addTemplate(PromptTemplate template) {
        if (template != null && template.isValid()) {
            templates.put(template.getId(), template);
            promptNames.put(template.getId(), template.getName());
            saveTemplates();
        }
    }
    
    public void updateTemplate(PromptTemplate template) {
        if (template != null && templates.containsKey(template.getId())) {
            templates.put(template.getId(), template);
            promptNames.put(template.getId(), template.getName());
            saveTemplates();
        }
    }
    
    public void removeTemplate(String id) {
        templates.remove(id);
        promptNames.remove(id);
        saveTemplates();
    }
    
    public PromptTemplate getTemplate(String id) {
        return templates.get(id);
    }
    
    public List<PromptTemplate> getAllTemplates() {
        return new ArrayList<>(templates.values());
    }
    
    public List<PromptTemplate> getTemplatesByCategory(String categoryId) {
        return templates.values().stream()
                .filter(t -> categoryId.equals(t.getCategory()))
                .collect(Collectors.toList());
    }
    
    public List<String> getTemplateIds() {
        return new ArrayList<>(templates.keySet());
    }
    
    public Map<String, String> getPromptNames() {
        return new LinkedHashMap<>(promptNames);
    }
    
    public void addCategory(PromptCategory category) {
        if (category != null) {
            categories.put(category.getId(), category);
            saveTemplates();
        }
    }
    
    public void removeCategory(String id) {
        categories.remove(id);
        saveTemplates();
    }
    
    public PromptCategory getCategory(String id) {
        return categories.get(id);
    }
    
    public List<PromptCategory> getAllCategories() {
        return new ArrayList<>(categories.values());
    }
    
    public List<String> getCategoryNames() {
        return categories.values().stream()
                .sorted(Comparator.comparingInt(PromptCategory::getOrder))
                .map(PromptCategory::getName)
                .collect(Collectors.toList());
    }
    
    public String renderTemplate(String id, Map<String, String> params) {
        PromptTemplate template = templates.get(id);
        if (template != null) {
            return template.render(params);
        }
        return null;
    }
    
    public String renderTemplate(String id) {
        return renderTemplate(id, null);
    }
    
    public boolean hasTemplate(String id) {
        return templates.containsKey(id);
    }
    
    public int getTemplateCount() {
        return templates.size();
    }
    
    public void importTemplates(String filePath) throws IOException {
        String content = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
        JSONObject json = new JSONObject(content);
        
        if (json.has("templates")) {
            JSONArray templatesArray = json.getJSONArray("templates");
            for (int i = 0; i < templatesArray.length(); i++) {
                JSONObject tplJson = templatesArray.getJSONObject(i);
                PromptTemplate template = PromptTemplate.fromJson(tplJson);
                if (template != null && template.isValid()) {
                    templates.put(template.getId(), template);
                    promptNames.put(template.getId(), template.getName());
                }
            }
        }
        
        saveTemplates();
    }
    
    public void exportTemplates(String filePath) throws IOException {
        JSONObject json = new JSONObject();
        
        JSONArray templatesArray = new JSONArray();
        for (PromptTemplate template : templates.values()) {
            templatesArray.put(template.toJson());
        }
        json.put("templates", templatesArray);
        
        String jsonStr = json.toString(2);
        Files.write(Paths.get(filePath), jsonStr.getBytes(StandardCharsets.UTF_8));
    }
    
    public void exportTemplatesByCategory(String filePath, String categoryId) throws IOException {
        JSONObject json = new JSONObject();
        
        JSONArray templatesArray = new JSONArray();
        for (PromptTemplate template : templates.values()) {
            if (categoryId.equals(template.getCategory())) {
                templatesArray.put(template.toJson());
            }
        }
        json.put("templates", templatesArray);
        
        String jsonStr = json.toString(2);
        Files.write(Paths.get(filePath), jsonStr.getBytes(StandardCharsets.UTF_8));
    }
    
    public List<PromptTemplate> searchTemplates(String keyword) {
        if (keyword == null || keyword.isEmpty()) {
            return getAllTemplates();
        }
        
        String lowerKeyword = keyword.toLowerCase();
        return templates.values().stream()
                .filter(t -> t.getName().toLowerCase().contains(lowerKeyword) ||
                             t.getTemplate().toLowerCase().contains(lowerKeyword) ||
                             (t.getDescription() != null && t.getDescription().toLowerCase().contains(lowerKeyword)))
                .collect(Collectors.toList());
    }
    
    public PromptTemplate createFromExisting(String existingId, String newId, String newName) {
        PromptTemplate existing = templates.get(existingId);
        if (existing == null) {
            return null;
        }
        
        PromptTemplate newTemplate = new PromptTemplate();
        newTemplate.setId(newId);
        newTemplate.setName(newName);
        newTemplate.setCategory(existing.getCategory());
        newTemplate.setTemplate(existing.getTemplate());
        newTemplate.setDescription(existing.getDescription());
        newTemplate.setVariables(existing.getVariables());
        newTemplate.setVariableDefaults(existing.getVariableDefaults());
        
        return newTemplate;
    }
    
    public static class PromptCategory {
        private String id;
        private String name;
        private String description;
        private int order;
        
        public PromptCategory() {
            this.order = 0;
        }
        
        public PromptCategory(String id, String name) {
            this.id = id;
            this.name = name;
            this.description = "";
            this.order = 0;
        }
        
        public static PromptCategory fromJson(JSONObject json) {
            if (json == null) return null;
            
            PromptCategory category = new PromptCategory();
            category.setId(json.optString("id", ""));
            category.setName(json.optString("name", ""));
            category.setDescription(json.optString("description", ""));
            category.setOrder(json.optInt("order", 0));
            
            return category;
        }
        
        public JSONObject toJson() {
            JSONObject json = new JSONObject();
            json.put("id", id);
            json.put("name", name);
            json.put("description", description);
            json.put("order", order);
            return json;
        }
        
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public int getOrder() { return order; }
        public void setOrder(int order) { this.order = order; }
    }
    
    public static class PromptTemplate {
        private String id;
        private String name;
        private String category;
        private String template;
        private List<String> variables;
        private String description;
        private Map<String, String> variableDefaults;
        
        public PromptTemplate() {
            this.variables = new ArrayList<>();
            this.variableDefaults = new HashMap<>();
        }
        
        public static PromptTemplate fromJson(JSONObject json) {
            if (json == null) return null;
            
            PromptTemplate tpl = new PromptTemplate();
            tpl.setId(json.optString("id", ""));
            tpl.setName(json.optString("name", ""));
            tpl.setCategory(json.optString("category", "other"));
            tpl.setTemplate(json.optString("template", ""));
            tpl.setDescription(json.optString("description", ""));
            
            JSONArray varsArray = json.optJSONArray("variables");
            if (varsArray != null) {
                List<String> vars = new ArrayList<>();
                for (int i = 0; i < varsArray.length(); i++) {
                    vars.add(varsArray.getString(i));
                }
                tpl.setVariables(vars);
            }
            
            JSONObject defaultsObj = json.optJSONObject("variableDefaults");
            if (defaultsObj != null) {
                Map<String, String> defaults = new HashMap<>();
                for (String key : defaultsObj.keySet()) {
                    defaults.put(key, defaultsObj.getString(key));
                }
                tpl.setVariableDefaults(defaults);
            }
            
            return tpl;
        }
        
        public JSONObject toJson() {
            JSONObject json = new JSONObject();
            json.put("id", id);
            json.put("name", name);
            json.put("category", category);
            json.put("template", template);
            json.put("description", description);
            
            JSONArray varsArray = new JSONArray();
            for (String var : variables) {
                varsArray.put(var);
            }
            json.put("variables", varsArray);
            
            if (!variableDefaults.isEmpty()) {
                JSONObject defaultsObj = new JSONObject();
                for (Map.Entry<String, String> entry : variableDefaults.entrySet()) {
                    defaultsObj.put(entry.getKey(), entry.getValue());
                }
                json.put("variableDefaults", defaultsObj);
            }
            
            return json;
        }
        
        private List<String> extractVariables(String template) {
            List<String> vars = new ArrayList<>();
            if (template == null) return vars;
            
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\{\\{([^}]+)\\}\\}");
            java.util.regex.Matcher matcher = pattern.matcher(template);
            
            while (matcher.find()) {
                String varName = matcher.group(1).trim();
                if (!vars.contains(varName)) {
                    vars.add(varName);
                }
            }
            return vars;
        }
        
        public String render(Map<String, String> params) {
            if (template == null) return "";
            
            String result = template;
            if (params != null) {
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    String placeholder = "{{" + entry.getKey() + "}}";
                    String value = entry.getValue() != null ? entry.getValue() : 
                        variableDefaults.getOrDefault(entry.getKey(), "");
                    result = result.replace(placeholder, value);
                }
            }
            
            for (String var : variables) {
                String placeholder = "{{" + var + "}}";
                if (result.contains(placeholder)) {
                    String defaultValue = variableDefaults.getOrDefault(var, "");
                    result = result.replace(placeholder, defaultValue);
                }
            }
            
            return result;
        }
        
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public String getTemplate() { return template; }
        public void setTemplate(String template) { 
            this.template = template; 
            this.variables = extractVariables(template);
        }
        public List<String> getVariables() { return new ArrayList<>(variables); }
        public void setVariables(List<String> variables) { this.variables = variables != null ? new ArrayList<>(variables) : new ArrayList<>(); }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public Map<String, String> getVariableDefaults() { return new HashMap<>(variableDefaults); }
        public void setVariableDefaults(Map<String, String> defaults) { this.variableDefaults = defaults != null ? new HashMap<>(defaults) : new HashMap<>(); }
        public boolean isValid() { return id != null && !id.isEmpty() && name != null && !name.isEmpty() && template != null && !template.isEmpty(); }
    }
}
