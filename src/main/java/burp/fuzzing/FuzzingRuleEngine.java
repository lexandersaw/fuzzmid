package burp.fuzzing;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

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
        // 整数型参数规则
        FuzzingRule integerRule = new FuzzingRule();
        integerRule.setId("integer_fuzz");
        integerRule.setName("数字型参数Fuzzing");
        integerRule.setDescription("针对整数型参数生成常见的测试值");
        integerRule.setCategory("参数类型");
        
        RuleCondition intCondition = new RuleCondition("param_type", RuleCondition.Operator.EQUALS, "integer");
        integerRule.setCondition(intCondition);
        
        List<String> intTemplates = new ArrayList<>();
        intTemplates.add("0");
        intTemplates.add("1");
        intTemplates.add("-1");
        intTemplates.add("1.5");
        intTemplates.add("999999999");
        integerRule.setTemplates(intTemplates);
        addRule(integerRule);
        
        // 字符串型参数规则
        FuzzingRule stringRule = new FuzzingRule();
        stringRule.setId("string_fuzz");
        stringRule.setName("字符串参数Fuzzing");
        stringRule.setDescription("针对字符串型参数生成常见的测试值");
        stringRule.setCategory("参数类型");
        
        RuleCondition strCondition = new RuleCondition("param_type", RuleCondition.Operator.EQUALS, "string");
        stringRule.setCondition(strCondition);
        
        List<String> strTemplates = new ArrayList<>();
        strTemplates.add("");
        strTemplates.add("test");
        strTemplates.add("<script>alert(1)</script>");
        strTemplates.add("' OR '1'='1");
        stringRule.setTemplates(strTemplates);
        addRule(stringRule);
        
        // 布尔型参数规则
        FuzzingRule boolRule = new FuzzingRule();
        boolRule.setId("boolean_fuzz");
        boolRule.setName("布尔型参数Fuzzing");
        boolRule.setDescription("针对布尔型参数生成测试值");
        boolRule.setCategory("参数类型");
        
        RuleCondition boolCondition = new RuleCondition("param_type", RuleCondition.Operator.EQUALS, "boolean");
        boolRule.setCondition(boolCondition);
        
        List<String> boolTemplates = new ArrayList<>();
        boolTemplates.add("true");
        boolTemplates.add("false");
        boolTemplates.add("1");
        boolTemplates.add("0");
        boolRule.setTemplates(boolTemplates);
        addRule(boolRule);
        
        // JSON参数规则
        FuzzingRule jsonRule = new FuzzingRule();
        jsonRule.setId("json_fuzz");
        jsonRule.setName("JSON参数Fuzzing");
        jsonRule.setDescription("针对JSON参数生成测试值");
        jsonRule.setCategory("参数类型");
        
        RuleCondition jsonCondition = new RuleCondition("param_type", RuleCondition.Operator.EQUALS, "json");
        jsonRule.setCondition(jsonCondition);
        
        List<String> jsonTemplates = new ArrayList<>();
        jsonTemplates.add("{}");
        jsonTemplates.add("[]");
        jsonTemplates.add("{\"test\":\"test\"}");
        jsonTemplates.add("[1,2,3]");
        jsonRule.setTemplates(jsonTemplates);
        addRule(jsonRule);
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
        
        JSONObject conditionJson = json.optJSONObject("condition");
        if (conditionJson != null) {
            RuleCondition condition = RuleCondition.fromJson(conditionJson);
            if (condition != null) {
                rule.setCondition(condition);
            }
        }
        
        JSONArray templatesArray = json.optJSONArray("templates");
        if (templatesArray != null) {
            List<String> templates = new ArrayList<>();
            for (int i = 0; i < templatesArray.length(); i++) {
                templates.add(templatesArray.optString(i, ""));
            }
            rule.setTemplates(templates);
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
        
        for (FuzzingRule rule : enabledRules) {
            RuleCondition condition = rule.getCondition();
            if (condition != null && condition.evaluate(context)) {
                allPayloads.addAll(rule.getTemplates());
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
