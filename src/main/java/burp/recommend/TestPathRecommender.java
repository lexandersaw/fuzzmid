package burp.recommend;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import burp.util.ContextAnalyzer.RequestContext;

public class TestPathRecommender {
    
    private final List<RecommendationRule> rules;
    
    public TestPathRecommender() {
        this.rules = new ArrayList<>();
        initializeDefaultRules();
    }
    
    private void initializeDefaultRules() {
        rules.add(new RecommendationRule(
            "login_auth_bypass",
            Pattern.compile("(?i)(login|signin|auth|authenticate)"),
            "认证绕过测试",
            "认证接口常见SQL注入和逻辑绕过",
            new String[]{"sqli_basic", "sqli_blind", "xss_reflected"},
            10
        ));
        
        rules.add(new RecommendationRule(
            "search_sqli",
            Pattern.compile("(?i)(search|query|find|filter)"),
            "SQL注入测试",
            "搜索功能常见SQL注入漏洞",
            new String[]{"sqli_basic", "sqli_error", "sqli_blind"},
            9
        ));
        
        rules.add(new RecommendationRule(
            "upload_traversal",
            Pattern.compile("(?i)(upload|file|attach|document)"),
            "文件上传/路径遍历测试",
            "文件上传功能常见路径遍历和文件类型绕过",
            new String[]{"path_traversal", "upload_names"},
            9
        ));
        
        rules.add(new RecommendationRule(
            "api_ssrf",
            Pattern.compile("(?i)(api|proxy|fetch|url|link|redirect)"),
            "SSRF/开放重定向测试",
            "URL参数常见SSRF和开放重定向漏洞",
            new String[]{"ssrf_payloads", "api_fuzzing"},
            8
        ));
        
        rules.add(new RecommendationRule(
            "form_xss",
            Pattern.compile("(?i)(form|input|comment|message|feedback)"),
            "XSS测试",
            "表单输入常见XSS漏洞",
            new String[]{"xss_reflected", "xss_stored"},
            8
        ));
        
        rules.add(new RecommendationRule(
            "admin_access",
            Pattern.compile("(?i)(admin|manage|config|setting|dashboard)"),
            "权限提升测试",
            "管理接口常见越权访问",
            new String[]{"api_fuzzing", "common_usernames"},
            9
        ));
        
        rules.add(new RecommendationRule(
            "export_injection",
            Pattern.compile("(?i)(export|download|report|generate)"),
            "注入/SSRF测试",
            "导出功能常见注入和SSRF",
            new String[]{"sqli_basic", "ssrf_payloads", "cmd_injection"},
            7
        ));
        
        rules.add(new RecommendationRule(
            "xml_xxe",
            Pattern.compile("(?i)(xml|soap|import|parse)"),
            "XXE测试",
            "XML处理常见XXE漏洞",
            new String[]{"xxe_payloads"},
            8
        ));
        
        rules.add(new RecommendationRule(
            "password_weak",
            Pattern.compile("(?i)(password|passwd|pwd|reset|change)"),
            "弱口令测试",
            "密码相关功能常见弱口令",
            new String[]{"cn_passwords", "common_usernames"},
            7
        ));
        
        rules.add(new RecommendationRule(
            "nosql_injection",
            Pattern.compile("(?i)(mongo|nosql|document)"),
            "NoSQL注入测试",
            "NoSQL相关接口常见注入",
            new String[]{"nosql_injection"},
            8
        ));
        
        rules.add(new RecommendationRule(
            "graphql_introspection",
            Pattern.compile("(?i)(graphql|gql)"),
            "GraphQL测试",
            "GraphQL接口常见内省和注入",
            new String[]{"graphql_injection"},
            8
        ));
        
        rules.add(new RecommendationRule(
            "jwt_security",
            Pattern.compile("(?i)(jwt|token|bearer|authorization)"),
            "JWT安全测试",
            "JWT认证常见安全漏洞",
            new String[]{"jwt_attacks"},
            8
        ));
    }
    
    public List<Recommendation> recommend(RequestContext context) {
        List<Recommendation> recommendations = new ArrayList<>();
        
        if (context == null || context.getPath() == null) {
            return recommendations;
        }
        
        String path = context.getPath();
        
        for (RecommendationRule rule : rules) {
            if (rule.matches(path)) {
                recommendations.add(new Recommendation(
                    rule.getName(),
                    rule.getDescription(),
                    rule.getPayloadTypes(),
                    rule.getPriority(),
                    rule.getId()
                ));
            }
        }
        
        if (context.getTechnologies() != null) {
            addTechBasedRecommendations(context, recommendations);
        }
        
        recommendations.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
        
        return recommendations;
    }
    
    private void addTechBasedRecommendations(RequestContext context, List<Recommendation> recommendations) {
        for (String tech : context.getTechnologies()) {
            String techLower = tech.toLowerCase();
            
            if (techLower.contains("java") || techLower.contains("spring")) {
                if (!hasRecommendation(recommendations, "deserialization")) {
                    recommendations.add(new Recommendation(
                        "Java反序列化测试",
                        "Java应用常见反序列化漏洞",
                        new String[]{"deserialization", "spring_actuator"},
                        7,
                        "java_deser"
                    ));
                }
            }
            
            if (techLower.contains("log4j")) {
                recommendations.add(new Recommendation(
                    "Log4j漏洞测试",
                    "Log4j存在远程代码执行漏洞",
                    new String[]{"log4j_payloads"},
                    10,
                    "log4j_rce"
                ));
            }
            
            if (techLower.contains("php") || techLower.contains("laravel") || techLower.contains("symfony")) {
                recommendations.add(new Recommendation(
                    "PHP模板注入测试",
                    "PHP应用常见SSTI漏洞",
                    new String[]{"ssti_payloads", "path_traversal"},
                    6,
                    "php_ssti"
                ));
            }
            
            if (techLower.contains("node") || techLower.contains("express")) {
                recommendations.add(new Recommendation(
                    "Node.js注入测试",
                    "Node.js应用常见原型污染和注入",
                    new String[]{"nosql_injection", "ssti_payloads"},
                    6,
                    "node_injection"
                ));
            }
        }
    }
    
    private boolean hasRecommendation(List<Recommendation> recommendations, String keyword) {
        for (Recommendation rec : recommendations) {
            for (String type : rec.getPayloadTypes()) {
                if (type.toLowerCase().contains(keyword.toLowerCase())) {
                    return true;
                }
            }
        }
        return false;
    }
    
    public void addRule(RecommendationRule rule) {
        if (rule != null) {
            rules.add(rule);
        }
    }
    
    public List<RecommendationRule> getRules() {
        return new ArrayList<>(rules);
    }
}
