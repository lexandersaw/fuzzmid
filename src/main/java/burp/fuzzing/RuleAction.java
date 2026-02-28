package burp.fuzzing;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RuleAction {
    
    private String id;
    private ActionType type;
    private String template;
    private List<String> templates;
    private int count;
    private boolean enabled;
    private Map<String, String> variables;
    
    public enum ActionType {
        STATIC,         // 静态值
        TEMPLATE,       // 模板生成
        RANGE,          // 范围生成
        DICTIONARY,     // 字典引用
        MUTATION,       // 变异生成
        COMPOSITE       // 组合生成
    }
    
    public RuleAction() {
        this.templates = new ArrayList<>();
        this.count = 1;
        this.enabled = true;
    }
    
    public RuleAction(String id, ActionType type, String template) {
        this();
        this.id = id;
        this.type = type;
        this.template = template;
    }
    
    public List<String> execute(FuzzingContext context) {
        List<String> results = new ArrayList<>();
        
        if (!enabled) {
            return results;
        }
        
        switch (type) {
            case STATIC:
                results.add(template != null ? template : "");
                break;
                
            case TEMPLATE:
                results.addAll(executeTemplate(context));
                break;
                
            case RANGE:
                results.addAll(executeRange(context));
                break;
                
            case DICTIONARY:
                results.addAll(executeDictionary(context));
                break;
                
            case MUTATION:
                results.addAll(executeMutation(context));
                break;
                
            case COMPOSITE:
                results.addAll(executeComposite(context));
                break;
        }
        
        return results;
    }
    
    private List<String> executeTemplate(FuzzingContext context) {
        List<String> results = new ArrayList<>();
        
        if (templates != null && !templates.isEmpty()) {
            for (String tpl : templates) {
                results.add(interpolate(tpl, context));
            }
        } else if (template != null) {
            results.add(interpolate(template, context));
        }
        
        return results;
    }
    
    private List<String> executeRange(FuzzingContext context) {
        List<String> results = new ArrayList<>();
        
        if (template == null) {
            return results;
        }
        
        // 解析范围格式: start:end:step 或 start-end
        String[] parts = template.split(":");
        if (parts.length >= 2) {
            try {
                int start = Integer.parseInt(interpolate(parts[0], context));
                int end = Integer.parseInt(interpolate(parts[1], context));
                int step = parts.length >= 3 ? Integer.parseInt(interpolate(parts[2], context)) : 1;
                
                for (int i = start; i <= end; i += step) {
                    results.add(String.valueOf(i));
                }
            } catch (NumberFormatException e) {
                // 字符范围
                char start = parts[0].charAt(0);
                char end = parts[1].charAt(0);
                for (char c = start; c <= end; c++) {
                    results.add(String.valueOf(c));
                }
            }
        }
        
        return results;
    }
    
    private List<String> executeDictionary(FuzzingContext context) {
        List<String> results = new ArrayList<>();
        
        // 从上下文获取字典
        if (template != null) {
            List<String> dict = context.getDictionary(template);
            if (dict != null) {
                results.addAll(dict);
            }
        }
        
        return results;
    }
    
    private List<String> executeMutation(FuzzingContext context) {
        List<String> results = new ArrayList<>();
        
        if (template != null) {
            String baseValue = interpolate(template, context);
            
            // 基本变异
            results.add(baseValue);
            results.add(baseValue.toUpperCase());
            results.add(baseValue.toLowerCase());
            
            // 常见编码
            results.add(urlEncode(baseValue));
            results.add(base64Encode(baseValue));
        }
        
        return results;
    }
    
    private List<String> executeComposite(FuzzingContext context) {
        List<String> results = new ArrayList<>();
        
        if (templates != null && templates.size() >= 2) {
            List<String> first = new ArrayList<>();
            List<String> second = new ArrayList<>();
            
            for (int i = 0; i < templates.size(); i++) {
                if (i < templates.size() / 2) {
                    first.add(interpolate(templates.get(i), context));
                } else {
                    second.add(interpolate(templates.get(i), context));
                }
            }
            
            for (String f : first) {
                for (String s : second) {
                    results.add(f + s);
                }
            }
        }
        
        return results;
    }
    
    private String interpolate(String template, FuzzingContext context) {
        if (template == null) return "";
        
        String result = template;
        
        // 替换上下文变量 {{variable}}
        Pattern pattern = Pattern.compile("\\{\\{(\\w+)\\}\\}");
        Matcher matcher = pattern.matcher(result);
        
        while (matcher.find()) {
            String varName = matcher.group(1);
            String varValue = context.getFieldValue(varName);
            if (varValue == null) {
                varValue = variables != null ? variables.get(varName) : "";
            }
            if (varValue == null) varValue = "";
            result = result.replace("{{" + varName + "}}", varValue);
        }
        
        return result;
    }
    
    private String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8");
        } catch (Exception e) {
            return value;
        }
    }
    
    private String base64Encode(String value) {
        return java.util.Base64.getEncoder().encodeToString(value.getBytes());
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public ActionType getType() {
        return type;
    }
    
    public void setType(ActionType type) {
        this.type = type;
    }
    
    public String getTemplate() {
        return template;
    }
    
    public void setTemplate(String template) {
        this.template = template;
    }
    
    public List<String> getTemplates() {
        return templates;
    }
    
    public void setTemplates(List<String> templates) {
        this.templates = templates;
    }
    
    public int getCount() {
        return count;
    }
    
    public void setCount(int count) {
        this.count = count;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public Map<String, String> getVariables() {
        return variables;
    }
    
    public void setVariables(Map<String, String> variables) {
        this.variables = variables;
    }
    
    @Override
    public String toString() {
        return "RuleAction{" +
                "id='" + id + '\'' +
                ", type=" + type +
                ", template='" + template + '\'' +
                ", enabled=" + enabled +
                '}';
    }
}
