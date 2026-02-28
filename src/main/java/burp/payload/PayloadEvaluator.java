package burp.payload;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class PayloadEvaluator {
    
    private final Map<String, Integer> knownPayloads;
    private final Map<String, Double> payloadScores;
    
    public PayloadEvaluator() {
        this.knownPayloads = new HashMap<>();
        this.payloadScores = new HashMap<>();
        initializeKnownPayloads();
    }
    
    private void initializeKnownPayloads() {
        // SQL注入高分payload
        knownPayloads.put("' OR 1=1--", 95);
        knownPayloads.put("' OR '1'='1", 92);
        knownPayloads.put("' UNION SELECT NULL--", 88);
        knownPayloads.put("1' AND '1'='1", 85);
        knownPayloads.put("admin'--", 82);
        knownPayloads.put("' OR ''='", 80);
        
        // XSS高分payload
        knownPayloads.put("<script>alert(1)</script>", 95);
        knownPayloads.put("<img src=x onerror=alert(1)>", 90);
        knownPayloads.put("javascript:alert(1)", 88);
        knownPayloads.put("<svg onload=alert(1)>", 87);
        knownPayloads.put("'\"><script>alert(1)</script>", 85);
        
        // 路径遍历高分payload
        knownPayloads.put("../../../etc/passwd", 90);
        knownPayloads.put("....//....//etc/passwd", 85);
        knownPayloads.put("..%2f..%2f..%2fetc/passwd", 83);
    }
    
    public EvaluationResult evaluate(String payload) {
        if (payload == null || payload.isEmpty()) {
            return new EvaluationResult(payload, 0, "空payload");
        }
        
        // 检查是否是已知的高分payload
        if (knownPayloads.containsKey(payload)) {
            int score = knownPayloads.get(payload);
            return new EvaluationResult(payload, score, "已知有效payload");
        }
        
        // 计算综合评分
        double versatilityScore = evaluateVersatility(payload);
        double bypassScore = evaluateBypassCapability(payload);
        double stealthScore = evaluateStealth(payload);
        double impactScore = evaluateImpact(payload);
        
        // 加权计算总分
        double totalScore = (versatilityScore * 0.25) + 
                           (bypassScore * 0.30) + 
                           (stealthScore * 0.20) + 
                           (impactScore * 0.25);
        
        int finalScore = (int) Math.round(totalScore);
        String description = generateDescription(versatilityScore, bypassScore, stealthScore, impactScore);
        
        return new EvaluationResult(payload, finalScore, description);
    }
    
    public List<EvaluationResult> evaluateAll(List<String> payloads) {
        List<EvaluationResult> results = new ArrayList<>();
        
        for (String payload : payloads) {
            results.add(evaluate(payload));
        }
        
        // 按分数排序
        results.sort((a, b) -> Integer.compare(b.getScore(), a.getScore()));
        
        return results;
    }
    
    private double evaluateVersatility(String payload) {
        double score = 50.0; // 基础分
        
        String lower = payload.toLowerCase();
        
        // 检测payload类型多样性
        if (lower.contains("'") || lower.contains("\"")) score += 10;
        if (lower.contains("<") || lower.contains(">")) score += 10;
        if (lower.contains("script") || lower.contains("javascript")) score += 5;
        if (lower.contains("select") || lower.contains("union")) score += 5;
        if (lower.contains("exec") || lower.contains("eval")) score += 5;
        
        // 通用性高的特征
        if (payload.length() < 20) score += 5;
        if (payload.length() < 10) score += 5;
        
        return Math.min(100, score);
    }
    
    private double evaluateBypassCapability(String payload) {
        double score = 40.0;
        
        // 编码和混淆特征
        if (payload.contains("%")) score += 15; // URL编码
        if (payload.contains("&#")) score += 10; // HTML实体
        if (payload.contains("\\u")) score += 10; // Unicode
        if (payload.contains("/**/")) score += 10; // SQL注释
        if (payload.contains("%00")) score += 8; // NULL字节
        
        // 大小写混合
        boolean hasMixedCase = false;
        for (char c : payload.toCharArray()) {
            if (Character.isLetter(c)) {
                hasMixedCase = true;
                break;
            }
        }
        if (hasMixedCase) {
            int upper = 0, lower = 0;
            for (char c : payload.toCharArray()) {
                if (Character.isUpperCase(c)) upper++;
                if (Character.isLowerCase(c)) lower++;
            }
            if (upper > 0 && lower > 0) score += 5;
        }
        
        // 特殊绕过技巧
        String lower = payload.toLowerCase();
        if (lower.contains("sel") && lower.contains("ect")) {
            if (!lower.contains("select")) score += 8; // 关键字拆分
        }
        if (lower.contains("un") && lower.contains("ion")) {
            if (!lower.contains("union")) score += 8;
        }
        
        return Math.min(100, score);
    }
    
    private double evaluateStealth(String payload) {
        double score = 60.0;
        
        // 越短越隐蔽
        if (payload.length() <= 5) score += 15;
        else if (payload.length() <= 10) score += 10;
        else if (payload.length() <= 20) score += 5;
        else if (payload.length() > 50) score -= 10;
        else if (payload.length() > 100) score -= 20;
        
        // 不含明显攻击特征
        String lower = payload.toLowerCase();
        if (!lower.contains("select")) score += 5;
        if (!lower.contains("script")) score += 5;
        if (!lower.contains("alert")) score += 5;
        if (!lower.contains("exec")) score += 5;
        
        // 正常字符为主
        int normalChars = 0;
        for (char c : payload.toCharArray()) {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
                (c >= '0' && c <= '9') || c == '/' || c == '-' || c == '_') {
                normalChars++;
            }
        }
        double normalRatio = (double) normalChars / payload.length();
        if (normalRatio > 0.8) score += 10;
        else if (normalRatio > 0.6) score += 5;
        
        return Math.min(100, Math.max(0, score));
    }
    
    private double evaluateImpact(String payload) {
        double score = 30.0;
        
        String lower = payload.toLowerCase();
        
        // 高危特征
        if (lower.contains("union") && lower.contains("select")) score += 20;
        if (lower.contains("script")) score += 15;
        if (lower.contains("alert") || lower.contains("confirm") || lower.contains("prompt")) score += 10;
        if (lower.contains("exec") || lower.contains("system") || lower.contains("eval")) score += 15;
        if (lower.contains("passwd") || lower.contains("shadow")) score += 12;
        if (lower.contains("etc/") || lower.contains("windows/")) score += 10;
        if (lower.contains("include") || lower.contains("require")) score += 10;
        
        // 危险函数
        if (lower.contains("load_file")) score += 12;
        if (lower.contains("into outfile")) score += 15;
        if (lower.contains("information_schema")) score += 10;
        if (lower.contains("document.cookie")) score += 12;
        if (lower.contains("xmlhttprequest")) score += 10;
        
        return Math.min(100, score);
    }
    
    private String generateDescription(double versatility, double bypass, double stealth, double impact) {
        StringBuilder desc = new StringBuilder();
        
        if (versatility >= 70) desc.append("通用性强 ");
        if (bypass >= 70) desc.append("绕过能力优秀 ");
        if (stealth >= 70) desc.append("隐蔽性高 ");
        if (impact >= 70) desc.append("危害程度高 ");
        
        if (desc.length() == 0) {
            if (versatility >= 50) desc.append("通用性一般 ");
            if (bypass >= 50) desc.append("有一定绕过能力 ");
            if (stealth >= 50) desc.append("隐蔽性一般 ");
            if (impact >= 50) desc.append("有一定危害 ");
        }
        
        return desc.toString().trim();
    }
    
    public void updatePayloadScore(String payload, int score) {
        payloadScores.put(payload, (double) score);
    }
    
    public void learnFromResult(String payload, boolean wasSuccessful) {
        Double currentScore = payloadScores.get(payload);
        if (currentScore == null) {
            currentScore = evaluate(payload).getScore() * 1.0;
        }
        
        if (wasSuccessful) {
            currentScore = Math.min(100, currentScore + 5);
        } else {
            currentScore = Math.max(0, currentScore - 2);
        }
        
        payloadScores.put(payload, currentScore);
    }
    
    public void addKnownPayload(String payload, int score) {
        knownPayloads.put(payload, score);
    }
    
    public static class EvaluationResult {
        private final String payload;
        private final int score;
        private final String description;
        private final Map<String, Double> detailedScores;
        
        public EvaluationResult(String payload, int score, String description) {
            this.payload = payload;
            this.score = score;
            this.description = description;
            this.detailedScores = new HashMap<>();
        }
        
        public String getPayload() { return payload; }
        public int getScore() { return score; }
        public String getDescription() { return description; }
        
        public void setDetailedScore(String dimension, double score) {
            detailedScores.put(dimension, score);
        }
        
        public Double getDetailedScore(String dimension) {
            return detailedScores.get(dimension);
        }
        
        public String getScoreLevel() {
            if (score >= 90) return "极高";
            if (score >= 80) return "高";
            if (score >= 70) return "中高";
            if (score >= 60) return "中";
            if (score >= 50) return "中低";
            return "低";
        }
        
        @Override
        public String toString() {
            return String.format("[%d分] %s - %s", score, payload, description);
        }
    }
}
