package burp.fuzzing;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

public class FuzzingRuleEngine {
    
    private final String configDirPath;
    private final String rulesFilePath;
    private final Map<String, FuzzingRule> rules;
    private final Map<String, Object> globalVariables;
    private boolean enabled;
    
    public FuzzingRuleEngine() {
        this.configDirPath = System.getProperty("user.home") + "/.config/fuzzMind";
        this.rulesFilePath = configDirPath + "/fuzzing_rules.json";
        this.rules = new LinkedHashMap<>();
        this.globalVariables = new HashMap<>();
        this.enabled = true;
        
        initializeDefaultRules();
    }
    
    private void initializeDefaultRules() {
        addRule(createNumberFuzzingRule("integer_fuzz", "数字型参数Fuzzing") {
            @Override
            protected FuzzingContext createContext(FuzzingContext context) {
                context.setParameter("param_type", "integer");
                context.setParameter("param_value", "123");
                return true;
            }
        });
        
        addRule(createNumberFuzzingRule("string_fuzz", "字符串参数Fuzzing") {
            @Override
            protected FuzzingContext createContext(FuzzingContext context) {
                context.setParameter("param_type", "string");
                context.setParameter("param_value", "test");
                return true;
            }
        });
        
        addRule(createNumberFuzzingRule("boolean_fuzz", "布尔型参数Fuzzing") {
            @Override
            protected FuzzingContext createContext(FuzzingContext context) {
                context.setParameter("param_type", "boolean");
                context.setParameter("param_value", "true");
                context.setParameter("param_value", "false");
                return true;
            }
        });
        
        addRule(createNumberFuzzingRule("json_fuzz", "JSON参数Fuzzing") {
            @Override
            protected FuzzingContext createContext(FuzzingContext context) {
                context.setParameter("param_type", "json");
                return true;
            }
        });
    }
    
    private void loadRules() {
        File rulesFile = new File(rulesFilePath);
        if (!rulesFile.exists()) {
            return;
        }
        
        try {
            String content = new String(Files.readAllBytes(Paths.get(rulesFilePath)), StandardCharsets.UTF_8);
            JSONObject json = new JSONObject(content);
            
            JSONArray rulesArray = json.optJSONArray("rules");
            if (rulesArray != null) {
                for (int i = 0; i < rulesArray.length(); i++) {
                    JSONObject ruleJson = rulesArray.getJSONObject(i);
                    FuzzingRule rule = parseRule(ruleJson);
                    if (rule != null) {
                        rules.put(rule.getId(), rule);
                    }
                }
            }
        } catch (Exception e) {
                System.err.println("Failed to load fuzzing rules: " + e.getMessage());
        }
    }
    
    private FuzzingRule parseRule(JSONObject json) {
        FuzzingRule rule = new FuzzingRule();
        
        rule.setId(json.optString("id", ""));
        rule.setName(json.optString("name", ""));
        rule.setDescription(json.optString("description", ""));
        rule.setEnabled(json.optBoolean("enabled", true));
        rule.setCategory(json.optString("category", ""));
        rule.setPriority(json.optInt("priority", 0));
        
        JSONObject conditionJson = json.optJSONObject("condition");
        if (conditionJson != null) {
            RuleCondition condition = new RuleCondition();
            condition.setField(conditionJson.optString("field", ""));
            condition.setOperator(RuleCondition.Operator.valueOf(conditionJson.optString("operator", "EQUALS")));
            condition.setValue(conditionJson.optString("value", ""));
            rule.setCondition(condition);
        }
        
        JSONArray actionsArray = json.optJSONArray("actions");
        if (actionsArray != null) {
            List<RuleAction> actions = new ArrayList<>();
            for (int i = 0; i < actionsArray.length(); i++) {
                JSONObject actionJson = actionsArray.getJSONObject(i);
                RuleAction action = new RuleAction();
                action.setId(actionJson.optString("id", ""));
                action.setType(RuleAction.ActionType.valueOf(actionJson.optString("type", "TEMPLATE")));
                action.setTemplate(actionJson.optString("template", ""));
                action.setEnabled(actionJson.optBoolean("enabled", true));
                actions.add(action);
            }
            rule.setActions(actions);
        }
        
        return rule;
    }
    
    public void saveRules() {
        try {
            File configDir = new File(configDirPath);
            if (!configDir.exists()) {
                configDir.mkdirs();
            }
            
            JSONObject root = new JSONObject();
            JSONArray rulesArray = new JSONArray();
            
            for (FuzzingRule rule : rules.values()) {
                rulesArray.put(rule.toJson());
            }
            
            root.put("rules", rulesArray);
            root.put("globalVariables", new JSONObject(globalVariables));
            
            String jsonStr = root.toString(2);
            Files.write(Paths.get(rulesFilePath), jsonStr.getBytes(StandardCharsets.UTF_8));
            
        } catch (Exception e) {
            System.err.println("Failed to save fuzzing rules: " + e.getMessage());
        }
    }
    
    public void addRule(FuzzingRule rule) {
        if (rule != null && rule.getId() != null) {
            rules.put(rule.getId(), rule);
            saveRules();
        }
    }
    
    public void removeRule(String ruleId) {
        rules.remove(ruleId);
        saveRules();
    }
    
    public FuzzingRule getRule(String ruleId) {
        return rules.get(ruleId);
    }
    
    public List<FuzzingRule> getAllRules() {
        return new ArrayList<>(rules.values());
    }
    
    public List<FuzzingRule> getEnabledRules() {
        List<FuzzingRule> enabledRules = new ArrayList<>();
        for (FuzzingRule rule : rules.values()) {
            if (rule.isEnabled()) {
                enabledRules.add(rule);
            }
        }
        return enabledRules;
    }
    
    public List<FuzzingRule> getRulesByCategory(String category) {
        List<FuzzingRule> categoryRules = new ArrayList<>();
        for (FuzzingRule rule : rules.values()) {
            if (category.equals(rule.getCategory())) {
                categoryRules.add(rule);
            }
        }
        return categoryRules;
    }
    
    public List<String> generatePayloads(FuzzingContext context) {
        List<String> allPayloads = new ArrayList<>();
        
        List<FuzzingRule> enabledRules = getEnabledRules();
        enabledRules.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
        
        for (FuzzingRule rule : enabledRules) {
            if (rule.matches(context)) {
                List<String> rulePayloads = rule.generatePayloads(context);
                allPayloads.addAll(rulePayloads);
            }
        }
        
        return allPayloads;
    }
    
    public void setGlobalVariable(String name, Object value) {
        globalVariables.put(name, value);
    }
    
    public Object getGlobalVariable(String name) {
        return globalVariables.get(name);
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void importRules(String filePath) throws IOException {
        String content = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
        JSONObject json = new JSONObject(content);
        
        JSONArray rulesArray = json.optJSONArray("rules");
        if (rulesArray != null) {
            for (int i = 0; i < rulesArray.length(); i++) {
                JSONObject ruleJson = rulesArray.getJSONObject(i);
                FuzzingRule rule = parseRule(ruleJson);
                if (rule != null) {
                rules.put(rule.getId(), rule);
                }
            }
        }
    }
    
    public void exportRules(String filePath) throws IOException {
        JSONArray rulesArray = new JSONArray();
        for (FuzzingRule rule : rules.values()) {
                rulesArray.put(rule.toJson());
            }
        
        JSONObject root = new JSONObject();
        root.put("rules", rulesArray);
        
        String jsonStr = root.toString(2);
        Files.write(Paths.get(filePath), jsonStr.getBytes(StandardCharsets.UTF_8));
    }
}
