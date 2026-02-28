package burp.payload;

import java.util.ArrayList;
import java.util.List;

public class MutationEngine {
    
    private final List<MutationRule> activeRules;
    private final PayloadMutator mutator;
    private MutationStrategy strategy;
    
    public enum MutationStrategy {
        SINGLE,      // 单次变异，每个payload只应用一个规则
        CHAIN,       // 链式变异，按顺序应用所有启用的规则
        COMBINATORIAL, // 组合变异，尝试所有规则组合
        SMART        // 智能变异，根据payload类型自动选择规则
    }
    
    public MutationEngine() {
        this.activeRules = new ArrayList<>();
        this.mutator = new PayloadMutator();
        this.strategy = MutationStrategy.CHAIN;
    }
    
    public MutationEngine(MutationStrategy strategy) {
        this.activeRules = new ArrayList<>();
        this.mutator = new PayloadMutator();
        this.strategy = strategy;
    }
    
    public List<String> process(String payload) {
        if (payload == null || payload.isEmpty()) {
            return new ArrayList<>();
        }
        
        switch (strategy) {
            case SINGLE:
                return processSingle(payload);
            case CHAIN:
                return processChain(payload);
            case COMBINATORIAL:
                return processCombinatorial(payload);
            case SMART:
                return processSmart(payload);
            default:
                return processChain(payload);
        }
    }
    
    private List<String> processSingle(String payload) {
        List<String> results = new ArrayList<>();
        results.add(payload);
        
        for (MutationRule rule : activeRules) {
            if (rule.isEnabled()) {
                try {
                    String mutated = rule.apply(payload);
                    if (!mutated.equals(payload) && !results.contains(mutated)) {
                        results.add(mutated);
                    }
                } catch (Exception e) {
                    // 忽略变异失败
                }
            }
        }
        
        return results;
    }
    
    private List<String> processChain(String payload) {
        List<String> results = new ArrayList<>();
        String current = payload;
        results.add(current);
        
        for (MutationRule rule : activeRules) {
            if (rule.isEnabled()) {
                try {
                    String mutated = rule.apply(current);
                    if (!mutated.equals(current)) {
                        current = mutated;
                        results.add(current);
                    }
                } catch (Exception e) {
                    // 忽略变异失败
                }
            }
        }
        
        return results;
    }
    
    private List<String> processCombinatorial(String payload) {
        List<String> results = new ArrayList<>();
        results.add(payload);
        
        List<MutationRule> enabledRules = new ArrayList<>();
        for (MutationRule rule : activeRules) {
            if (rule.isEnabled()) {
                enabledRules.add(rule);
            }
        }
        
        if (enabledRules.isEmpty()) {
            return results;
        }
        
        // 生成所有非空子集
        for (int i = 1; i < (1 << enabledRules.size()); i++) {
            String current = payload;
            
            for (int j = 0; j < enabledRules.size(); j++) {
                if ((i & (1 << j)) != 0) {
                    try {
                        current = enabledRules.get(j).apply(current);
                    } catch (Exception e) {
                        break;
                    }
                }
            }
            
            if (!results.contains(current)) {
                results.add(current);
            }
            
            if (results.size() > 1000) {
                break;
            }
        }
        
        return results;
    }
    
    private List<String> processSmart(String payload) {
        List<String> results = new ArrayList<>();
        results.add(payload);
        
        String lowerPayload = payload.toLowerCase();
        
        // SQL注入相关规则
        if (isSqlRelated(lowerPayload)) {
            applySqlRules(payload, results);
        }
        
        // XSS相关规则
        if (isXssRelated(lowerPayload)) {
            applyXssRules(payload, results);
        }
        
        // 路径遍历相关
        if (isPathTraversalRelated(lowerPayload)) {
            applyPathTraversalRules(payload, results);
        }
        
        // 通用规则
        for (MutationRule rule : activeRules) {
            if (rule.isEnabled() && !isTypeSpecificRule(rule)) {
                try {
                    String mutated = rule.apply(payload);
                    if (!mutated.equals(payload) && !results.contains(mutated)) {
                        results.add(mutated);
                    }
                } catch (Exception e) {
                    // 忽略变异失败
                }
            }
        }
        
        return results;
    }
    
    private boolean isSqlRelated(String payload) {
        return payload.contains("select") || payload.contains("union") ||
               payload.contains("or ") || payload.contains("and ") ||
               payload.contains("'") || payload.contains("--") ||
               payload.contains("/*") || payload.contains("order by") ||
               payload.contains("group by") || payload.contains("having");
    }
    
    private boolean isXssRelated(String payload) {
        return payload.contains("<script") || payload.contains("javascript:") ||
               payload.contains("onerror") || payload.contains("onload") ||
               payload.contains("onclick") || payload.contains("onmouse") ||
               payload.contains("<img") || payload.contains("<svg") ||
               payload.contains("<iframe") || payload.contains("alert(");
    }
    
    private boolean isPathTraversalRelated(String payload) {
        return payload.contains("../") || payload.contains("..\\") ||
               payload.contains("%2e%2e") || payload.contains("....//");
    }
    
    private boolean isTypeSpecificRule(MutationRule rule) {
        MutationRule.Type type = rule.getType();
        return type == MutationRule.Type.SQL_QUOTE_REPLACE ||
               type == MutationRule.Type.SQL_LOGIC_EQUIV ||
               type == MutationRule.Type.XSS_EVENT_REPLACE;
    }
    
    private void applySqlRules(String payload, List<String> results) {
        for (MutationRule rule : activeRules) {
            if (rule.isEnabled() && isSqlRule(rule)) {
                try {
                    String mutated = rule.apply(payload);
                    if (!mutated.equals(payload) && !results.contains(mutated)) {
                        results.add(mutated);
                    }
                } catch (Exception e) {
                    // 忽略变异失败
                }
            }
        }
    }
    
    private void applyXssRules(String payload, List<String> results) {
        for (MutationRule rule : activeRules) {
            if (rule.isEnabled() && isXssRule(rule)) {
                try {
                    String mutated = rule.apply(payload);
                    if (!mutated.equals(payload) && !results.contains(mutated)) {
                        results.add(mutated);
                    }
                } catch (Exception e) {
                    // 忽略变异失败
                }
            }
        }
    }
    
    private void applyPathTraversalRules(String payload, List<String> results) {
        for (MutationRule rule : activeRules) {
            if (rule.isEnabled() && isPathTraversalRule(rule)) {
                try {
                    String mutated = rule.apply(payload);
                    if (!mutated.equals(payload) && !results.contains(mutated)) {
                        results.add(mutated);
                    }
                } catch (Exception e) {
                    // 忽略变异失败
                }
            }
        }
    }
    
    private boolean isSqlRule(MutationRule rule) {
        MutationRule.Type type = rule.getType();
        return type == MutationRule.Type.CHAR_REPLACE ||
               type == MutationRule.Type.LOGIC_EQUIV ||
               type == MutationRule.Type.FUNC_REPLACE ||
               type == MutationRule.Type.COMMENT_INJECT ||
               type == MutationRule.Type.WHITESPACE_REPLACE ||
               type == MutationRule.Type.DOUBLE_WRITE ||
               type == MutationRule.Type.NULL_BYTE;
    }
    
    private boolean isXssRule(MutationRule rule) {
        MutationRule.Type type = rule.getType();
        return type == MutationRule.Type.XSS_EVENT_REPLACE ||
               type == MutationRule.Type.HTML_ENTITY_ENCODE ||
               type == MutationRule.Type.UNICODE_ENCODE ||
               type == MutationRule.Type.URL_ENCODE_KEYWORDS;
    }
    
    private boolean isPathTraversalRule(MutationRule rule) {
        MutationRule.Type type = rule.getType();
        return type == MutationRule.Type.URL_ENCODE_KEYWORDS ||
               type == MutationRule.Type.CHAR_REPLACE;
    }
    
    public void addRule(MutationRule rule) {
        if (rule != null) {
            activeRules.add(rule);
        }
    }
    
    public void removeRule(String ruleName) {
        activeRules.removeIf(r -> r.getName().equals(ruleName));
    }
    
    public void clearRules() {
        activeRules.clear();
    }
    
    public List<String> getActiveRuleNames() {
        List<String> names = new ArrayList<>();
        for (MutationRule rule : activeRules) {
            if (rule.isEnabled()) {
                names.add(rule.getName());
            }
        }
        return names;
    }
    
    public MutationStrategy getStrategy() {
        return strategy;
    }
    
    public void setStrategy(MutationStrategy strategy) {
        this.strategy = strategy;
    }
    
    public PayloadMutator getMutator() {
        return mutator;
    }
}
