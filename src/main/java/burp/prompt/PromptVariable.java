package burp.prompt;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PromptVariable {
    
    private String name;
    private String displayName;
    private String description;
    private String defaultValue;
    private boolean required;
    private List<String> options;
    private VariableType type;
    
    public enum VariableType {
        TEXT,
        SELECT,
        MULTI_SELECT,
        NUMBER,
        BOOLEAN
    }
    
    public PromptVariable() {
        this.required = false;
        this.type = VariableType.TEXT;
        this.options = new ArrayList<>();
    }
    
    public PromptVariable(String name, String displayName) {
        this();
        this.name = name;
        this.displayName = displayName;
    }
    
    public PromptVariable(String name, String displayName, String defaultValue) {
        this(name, displayName);
        this.defaultValue = defaultValue;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDisplayName() {
        return displayName;
    }
    
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public String getDefaultValue() {
        return defaultValue;
    }
    
    public void setDefaultValue(String defaultValue) {
        this.defaultValue = defaultValue;
    }
    
    public boolean isRequired() {
        return required;
    }
    
    public void setRequired(boolean required) {
        this.required = required;
    }
    
    public VariableType getType() {
        return type;
    }
    
    public void setType(VariableType type) {
        this.type = type;
    }
    
    public List<String> getOptions() {
        return new ArrayList<>(options);
    }
    
    public void setOptions(List<String> options) {
        this.options = options != null ? new ArrayList<>(options) : new ArrayList<>();
    }
    
    public void addOption(String option) {
        if (option != null && !options.contains(option)) {
            options.add(option);
        }
    }
    
    public boolean isValidValue(String value) {
        if (value == null || value.isEmpty()) {
            return !required;
        }
        
        switch (type) {
            case SELECT:
            case MULTI_SELECT:
                return options.contains(value);
            case NUMBER:
                try {
                    Double.parseDouble(value);
                    return true;
                } catch (NumberFormatException e) {
                    return false;
                }
            case BOOLEAN:
                return "true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value);
            case TEXT:
            default:
                return true;
        }
    }
    
    public String getPlaceholder() {
        switch (type) {
            case SELECT:
                return "请选择" + displayName;
            case NUMBER:
                return "请输入" + displayName;
            case BOOLEAN:
                return "是/否";
            case TEXT:
            default:
                return "请输入" + displayName;
        }
    }
    
    @Override
    public String toString() {
        return "PromptVariable{" +
                "name='" + name + '\'' +
                ", displayName='" + displayName + '\'' +
                ", type=" + type +
                ", required=" + required +
                '}';
    }
}
