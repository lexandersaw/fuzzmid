package burp.prompt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PromptTemplate {
    
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
    
    public PromptTemplate(String id, String name, String category, String template) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.template = template;
        this.variables = extractVariables(template);
        this.description = "";
        this.variableDefaults = new HashMap<>();
    }
    
    public PromptTemplate(String id, String name, String category, String template, List<String> variables) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.template = template;
        this.variables = variables != null ? new ArrayList<>(variables) : new ArrayList<>();
        this.description = "";
        this.variableDefaults = new HashMap<>();
    }
    
    private List<String> extractVariables(String template) {
        List<String> vars = new ArrayList<>();
        if (template == null) {
            return vars;
        }
        
        Pattern pattern = Pattern.compile("\\{\\{([^}]+)\\}\\}");
        Matcher matcher = pattern.matcher(template);
        
        while (matcher.find()) {
            String varName = matcher.group(1).trim();
            if (!vars.contains(varName)) {
                vars.add(varName);
            }
        }
        
        return vars;
    }
    
    public String render(Map<String, String> params) {
        if (template == null) {
            return "";
        }
        
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
    
    public String render() {
        return render(new HashMap<>());
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
    
    public String getCategory() {
        return category;
    }
    
    public void setCategory(String category) {
        this.category = category;
    }
    
    public String getTemplate() {
        return template;
    }
    
    public void setTemplate(String template) {
        this.template = template;
        this.variables = extractVariables(template);
    }
    
    public List<String> getVariables() {
        return new ArrayList<>(variables);
    }
    
    public void setVariables(List<String> variables) {
        this.variables = variables != null ? new ArrayList<>(variables) : new ArrayList<>();
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public Map<String, String> getVariableDefaults() {
        return new HashMap<>(variableDefaults);
    }
    
    public void setVariableDefaults(Map<String, String> defaults) {
        this.variableDefaults = defaults != null ? new HashMap<>(defaults) : new HashMap<>();
    }
    
    public void setVariableDefault(String varName, String defaultValue) {
        variableDefaults.put(varName, defaultValue);
    }
    
    public String getVariableDefault(String varName) {
        return variableDefaults.get(varName);
    }
    
    public boolean hasVariables() {
        return !variables.isEmpty();
    }
    
    public boolean isValid() {
        return id != null && !id.isEmpty() && 
               name != null && !name.isEmpty() && 
               template != null && !template.isEmpty();
    }
    
    @Override
    public String toString() {
        return "PromptTemplate{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", category='" + category + '\'' +
                ", variables=" + variables +
                '}';
    }
}
