package burp.payload;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import burp.AppConfig;

public class PayloadMutator {
    
    private final List<MutationRule> rules;
    private final Random random;
    private int maxDepth;
    private int maxVariants;
    
    public PayloadMutator() {
        this.rules = new ArrayList<>();
        this.random = new Random();
        this.maxDepth = 2;
        this.maxVariants = AppConfig.MAX_PAYLOAD_VARIANTS;
        
        initializeDefaultRules();
    }
    
    public PayloadMutator(int maxDepth, int maxVariants) {
        this.rules = new ArrayList<>();
        this.random = new Random();
        this.maxDepth = Math.min(maxDepth, AppConfig.MAX_MUTATION_DEPTH);
        this.maxVariants = Math.min(maxVariants, AppConfig.MAX_PAYLOAD_VARIANTS);
        
        initializeDefaultRules();
    }
    
    private void initializeDefaultRules() {
        // SQL 注入字符替换规则
        addRule(new MutationRule("sql_quote_replace", MutationRule.Type.CHAR_REPLACE) {
            @Override
            public String apply(String payload) {
                return payload.replace("'", "'")
                             .replace("'", "'")
                             .replace("\"", "\"")
                             .replace("\"", "\"");
            }
        });
        
        // 逻辑等价替换
        addRule(new MutationRule("sql_logic_eq", MutationRule.Type.LOGIC_EQUIV) {
            @Override
            public String apply(String payload) {
                return payload.replace("OR 1=1", "OR '1'='1'")
                             .replace("or 1=1", "or '1'='1'")
                             .replace("OR 1 = 1", "OR '1'='1'")
                             .replace("AND 1=1", "AND '1'='1'")
                             .replace("and 1=1", "and '1'='1'");
            }
        });
        
        // 函数替换
        addRule(new MutationRule("sql_func_replace", MutationRule.Type.FUNC_REPLACE) {
            @Override
            public String apply(String payload) {
                return payload.replace("SELECT", "(SELECT)")
                             .replace("select", "(select)")
                             .replace("UNION", "/*!UNION*/")
                             .replace("union", "/*!union*/");
            }
        });
        
        // 注释插入
        addRule(new MutationRule("comment_inject", MutationRule.Type.COMMENT_INJECT) {
            @Override
            public String apply(String payload) {
                if (payload.toUpperCase().contains("SELECT")) {
                    return payload.replace("SELECT", "SEL/**/ECT")
                                 .replace("select", "sel/**/ect");
                }
                return payload;
            }
        });
        
        // 空白替代
        addRule(new MutationRule("whitespace_replace", MutationRule.Type.WHITESPACE_REPLACE) {
            @Override
            public String apply(String payload) {
                return payload.replace(" ", "%09")
                             .replace(" ", "%0a")
                             .replace(" ", "%0d")
                             .replace(" ", "%0b")
                             .replace(" ", "/**/");
            }
        });
        
        // 双写绕过
        addRule(new MutationRule("double_write", MutationRule.Type.DOUBLE_WRITE) {
            @Override
            public String apply(String payload) {
                if (payload.contains("SELECT")) {
                    return payload.replace("SELECT", "SELSELECTECT");
                }
                if (payload.contains("UNION")) {
                    return payload.replace("UNION", "UNIUNIONON");
                }
                return payload;
            }
        });
        
        // 大小写混合
        addRule(new MutationRule("case_mixed", MutationRule.Type.CASE_MIXED) {
            @Override
            public String apply(String payload) {
                StringBuilder result = new StringBuilder();
                for (char c : payload.toCharArray()) {
                    if (Character.isLetter(c)) {
                        result.append(random.nextBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
                    } else {
                        result.append(c);
                    }
                }
                return result.toString();
            }
        });
        
        // NULL字节注入
        addRule(new MutationRule("null_byte", MutationRule.Type.NULL_BYTE) {
            @Override
            public String apply(String payload) {
                if (payload.startsWith("'") || payload.startsWith("\"")) {
                    return payload.substring(0, 1) + "%00" + payload.substring(1);
                }
                return payload;
            }
        });
        
        // 括号包装
        addRule(new MutationRule("paren_wrap", MutationRule.Type.PAREN_WRAP) {
            @Override
            public String apply(String payload) {
                if (!payload.startsWith("(") && !payload.endsWith(")")) {
                    return "(" + payload + ")";
                }
                return payload;
            }
        });
        
        // URL编码关键字
        addRule(new MutationRule("url_encode_keywords", MutationRule.Type.URL_ENCODE_KEYWORDS) {
            @Override
            public String apply(String payload) {
                return payload.replace("SELECT", "%53%45%4C%45%43%54")
                             .replace("UNION", "%55%4E%49%4F%4E")
                             .replace("WHERE", "%57%48%45%52%45")
                             .replace("AND", "%41%4E%44")
                             .replace("OR", "%4F%52");
            }
        });
        
        // XSS事件处理器替换
        addRule(new MutationRule("xss_event_replace", MutationRule.Type.XSS_EVENT_REPLACE) {
            @Override
            public String apply(String payload) {
                return payload.replace("onerror", "onerror")
                             .replace("onload", "onload")
                             .replace("onclick", "onclick")
                             .replace("onmouseover", "onmouseover");
            }
        });
        
        // HTML实体编码
        addRule(new MutationRule("html_entity_encode", MutationRule.Type.HTML_ENTITY_ENCODE) {
            @Override
            public String apply(String payload) {
                StringBuilder result = new StringBuilder();
                for (char c : payload.toCharArray()) {
                    if (c == '<') {
                        result.append("&#60;");
                    } else if (c == '>') {
                        result.append("&#62;");
                    } else if (c == '"') {
                        result.append("&#34;");
                    } else if (c == '\'') {
                        result.append("&#39;");
                    } else {
                        result.append(c);
                    }
                }
                return result.toString();
            }
        });
        
        // Unicode编码
        addRule(new MutationRule("unicode_encode", MutationRule.Type.UNICODE_ENCODE) {
            @Override
            public String apply(String payload) {
                StringBuilder result = new StringBuilder();
                for (char c : payload.toCharArray()) {
                    if (c == '<') {
                        result.append("\\u003c");
                    } else if (c == '>') {
                        result.append("\\u003e");
                    } else if (c == '"') {
                        result.append("\\u0022");
                    } else if (c == '\'') {
                        result.append("\\u0027");
                    } else {
                        result.append(c);
                    }
                }
                return result.toString();
            }
        });
    }
    
    public void addRule(MutationRule rule) {
        if (rule != null) {
            rules.add(rule);
        }
    }
    
    public void removeRule(String ruleName) {
        rules.removeIf(r -> r.getName().equals(ruleName));
    }
    
    public List<String> mutate(String payload, int depth) {
        Set<String> variantSet = new LinkedHashSet<>();
        variantSet.add(payload);
        
        if (depth <= 0 || depth > maxDepth) {
            return new ArrayList<>(variantSet);
        }
        
        for (MutationRule rule : rules) {
            if (rule.isEnabled()) {
                try {
                    String mutated = rule.apply(payload);
                    if (!mutated.equals(payload)) {
                        variantSet.add(mutated);
                        
                        if (variantSet.size() >= maxVariants) {
                            return new ArrayList<>(variantSet);
                        }
                    }
                } catch (Exception e) {
                }
            }
        }
        
        return new ArrayList<>(variantSet);
    }
    
    public List<String> mutateDeep(String payload, int depth) {
        Set<String> resultSet = new LinkedHashSet<>();
        List<String> currentLevel = new ArrayList<>();
        currentLevel.add(payload);
        resultSet.add(payload);
        
        for (int i = 0; i < depth && i < maxDepth; i++) {
            List<String> nextLevel = new ArrayList<>();
            
            for (String currentPayload : currentLevel) {
                for (MutationRule rule : rules) {
                    if (rule.isEnabled()) {
                        try {
                            String mutated = rule.apply(currentPayload);
                            if (!mutated.equals(currentPayload) && !resultSet.contains(mutated)) {
                                nextLevel.add(mutated);
                                resultSet.add(mutated);
                                
                                if (resultSet.size() >= maxVariants) {
                                    return new ArrayList<>(resultSet);
                                }
                            }
                        } catch (Exception e) {
                        }
                    }
                }
            }
            
            currentLevel = nextLevel;
            if (currentLevel.isEmpty()) {
                break;
            }
        }
        
        return new ArrayList<>(resultSet);
    }
    
    public List<String> mutateList(List<String> payloads, int depth) {
        Set<String> resultSet = new LinkedHashSet<>();
        
        for (String payload : payloads) {
            List<String> variants = mutateDeep(payload, depth);
            resultSet.addAll(variants);
            
            if (resultSet.size() >= maxVariants) {
                break;
            }
        }
        
        List<String> result = new ArrayList<>(resultSet);
        if (result.size() > maxVariants) {
            return result.subList(0, maxVariants);
        }
        
        return result;
    }
    
    public List<String> mutateWithRules(String payload, List<String> ruleNames, int depth) {
        Set<String> variantSet = new LinkedHashSet<>();
        variantSet.add(payload);
        
        if (depth <= 0) {
            return new ArrayList<>(variantSet);
        }
        
        for (String ruleName : ruleNames) {
            for (MutationRule rule : rules) {
                if (rule.getName().equals(ruleName) && rule.isEnabled()) {
                    try {
                        String mutated = rule.apply(payload);
                        if (!mutated.equals(payload)) {
                            variantSet.add(mutated);
                        }
                    } catch (Exception e) {
                    }
                    break;
                }
            }
        }
        
        return new ArrayList<>(variantSet);
    }
    
    public List<String> getRuleNames() {
        List<String> names = new ArrayList<>();
        for (MutationRule rule : rules) {
            names.add(rule.getName());
        }
        return names;
    }
    
    public void setRuleEnabled(String ruleName, boolean enabled) {
        for (MutationRule rule : rules) {
            if (rule.getName().equals(ruleName)) {
                rule.setEnabled(enabled);
                break;
            }
        }
    }
    
    public int getMaxDepth() {
        return maxDepth;
    }
    
    public void setMaxDepth(int maxDepth) {
        this.maxDepth = Math.max(1, Math.min(maxDepth, AppConfig.MAX_MUTATION_DEPTH));
    }
    
    public int getMaxVariants() {
        return maxVariants;
    }
    
    public void setMaxVariants(int maxVariants) {
        this.maxVariants = Math.max(1, Math.min(maxVariants, AppConfig.MAX_PAYLOAD_VARIANTS));
    }
    
    public int estimateVariantCount(int payloadCount, int depth) {
        int rulesPerLevel = 0;
        for (MutationRule rule : rules) {
            if (rule.isEnabled()) {
                rulesPerLevel++;
            }
        }
        
        if (rulesPerLevel == 0) return payloadCount;
        
        double estimate = payloadCount * Math.pow(rulesPerLevel, Math.min(depth, maxDepth));
        return (int) Math.min(estimate, maxVariants);
    }
}
