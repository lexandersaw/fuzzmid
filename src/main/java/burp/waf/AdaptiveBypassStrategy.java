package burp.waf;

import java.util.*;
import java.util.regex.Pattern;

public class AdaptiveBypassStrategy {
    
    private final Map<String, List<BypassTechnique>> wafStrategies;
    private final Map<String, Integer> techniqueSuccessRates;
    private final Map<String, Long> lastAttemptTimes;
    
    public AdaptiveBypassStrategy() {
        this.wafStrategies = new LinkedHashMap<>();
        this.techniqueSuccessRates = new HashMap<>();
        this.lastAttemptTimes = new HashMap<>();
        
        initializeDefaultStrategies();
    }
    
    private void initializeDefaultStrategies() {
        // Cloudflare 绕过策略
        List<BypassTechnique> cloudflareTechniques = new ArrayList<>();
        cloudflareTechniques.add(new BypassTechnique("chunked_encoding", "分块传输编码", 80));
        cloudflareTechniques.add(new BypassTechnique("case_variation", "大小写变换", 70));
        cloudflareTechniques.add(new BypassTechnique("unicode_normalization", "Unicode规范化", 65));
        cloudflareTechniques.add(new BypassTechnique("http_version", "HTTP版本差异", 60));
        cloudflareTechniques.add(new BypassTechnique("multipart_boundary", "Multipart边界", 55));
        wafStrategies.put("cloudflare", cloudflareTechniques);
        
        // ModSecurity 绕过策略
        List<BypassTechnique> modsecTechniques = new ArrayList<>();
        modsecTechniques.add(new BypassTechnique("comment_injection", "注释注入", 85));
        modsecTechniques.add(new BypassTechnique("encoding_chain", "编码链", 80));
        modsecTechniques.add(new BypassTechnique("null_byte", "NULL字节注入", 75));
        modsecTechniques.add(new BypassTechnique("case_variation", "大小写变换", 70));
        modsecTechniques.add(new BypassTechnique("double_url_encode", "双重URL编码", 65));
        wafStrategies.put("modsecurity", modsecTechniques);
        
        // AWS WAF 绕过策略
        List<BypassTechnique> awsTechniques = new ArrayList<>();
        awsTechniques.add(new BypassTechnique("chunked_encoding", "分块传输编码", 75));
        awsTechniques.add(new BypassTechnique("http_version", "HTTP版本差异", 70));
        awsTechniques.add(new BypassTechnique("encoding_variation", "编码变体", 65));
        wafStrategies.put("awswaf", awsTechniques);
        
        // 安全狗 绕过策略
        List<BypassTechnique> safedogTechniques = new ArrayList<>();
        safedogTechniques.add(new BypassTechnique("double_url_encode", "双重URL编码", 85));
        safedogTechniques.add(new BypassTechnique("unicode_encode", "Unicode编码", 80));
        safedogTechniques.add(new BypassTechnique("h_w_event_attack", "H-W事件攻击", 75));
        safedogTechniques.add(new BypassTechnique("multipart_boundary", "Multipart边界", 70));
        wafStrategies.put("safedog", safedogTechniques);
        
        // 云锁 绕过策略
        List<BypassTechnique> yunsuoTechniques = new ArrayList<>();
        yunsuoTechniques.add(new BypassTechnique("chunked_encoding", "分块传输编码", 80));
        yunsuoTechniques.add(new BypassTechnique("multipart_boundary", "Multipart边界", 75));
        yunsuoTechniques.add(new BypassTechnique("url_encode", "URL编码变体", 70));
        wafStrategies.put("yunsuo", yunsuoTechniques);
        
        // 绿盟 绕过策略
        List<BypassTechnique> nsfocusTechniques = new ArrayList<>();
        nsfocusTechniques.add(new BypassTechnique("encoding_chain", "编码链", 80));
        nsfocusTechniques.add(new BypassTechnique("case_variation", "大小写变换", 75));
        nsfocusTechniques.add(new BypassTechnique("comment_injection", "注释注入", 70));
        wafStrategies.put("nsfocus", nsfocusTechniques);
        
        // 通用绕过策略
        List<BypassTechnique> genericTechniques = new ArrayList<>();
        genericTechniques.add(new BypassTechnique("url_encode", "URL编码", 60));
        genericTechniques.add(new BypassTechnique("double_url_encode", "双重URL编码", 55));
        genericTechniques.add(new BypassTechnique("unicode_encode", "Unicode编码", 50));
        genericTechniques.add(new BypassTechnique("html_entity_encode", "HTML实体编码", 45));
        genericTechniques.add(new BypassTechnique("base64_encode", "Base64编码", 40));
        genericTechniques.add(new BypassTechnique("case_variation", "大小写变换", 35));
        genericTechniques.add(new BypassTechnique("comment_injection", "注释注入", 30));
        genericTechniques.add(new BypassTechnique("null_byte", "NULL字节", 25));
        wafStrategies.put("generic", genericTechniques);
    }
    
    public List<BypassTechnique> getStrategiesForWAF(String wafId) {
        if (wafId == null || wafId.isEmpty()) {
            return wafStrategies.getOrDefault("generic", new ArrayList<>());
        }
        
        List<BypassTechnique> strategies = wafStrategies.get(wafId.toLowerCase());
        if (strategies == null || strategies.isEmpty()) {
            return wafStrategies.getOrDefault("generic", new ArrayList<>());
        }
        
        return new ArrayList<>(strategies);
    }
    
    public List<BypassTechnique> getTopStrategies(String wafId, int limit) {
        List<BypassTechnique> strategies = getStrategiesForWAF(wafId);
        
        strategies.sort((a, b) -> {
            int successCompare = Integer.compare(
                getSuccessRate(b.getId()), 
                getSuccessRate(a.getId())
            );
            if (successCompare != 0) return successCompare;
            return Integer.compare(b.getBaseSuccessRate(), a.getBaseSuccessRate());
        });
        
        if (limit > 0 && strategies.size() > limit) {
            return strategies.subList(0, limit);
        }
        
        return strategies;
    }
    
    public String applyTechnique(String payload, String techniqueId) {
        if (payload == null || payload.isEmpty()) {
            return payload;
        }
        
        switch (techniqueId) {
            case "url_encode":
                return urlEncode(payload);
            case "double_url_encode":
                return urlEncode(urlEncode(payload));
            case "unicode_encode":
                return unicodeEncode(payload);
            case "html_entity_encode":
                return htmlEntityEncode(payload);
            case "base64_encode":
                return base64Encode(payload);
            case "case_variation":
                return caseVariation(payload);
            case "comment_injection":
                return commentInjection(payload);
            case "null_byte":
                return nullByteInjection(payload);
            case "chunked_encoding":
                return payload;
            case "multipart_boundary":
                return payload;
            default:
                return payload;
        }
    }
    
    private String urlEncode(String payload) {
        try {
            return java.net.URLEncoder.encode(payload, "UTF-8");
        } catch (Exception e) {
            return payload;
        }
    }
    
    private String unicodeEncode(String payload) {
        StringBuilder result = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (c == '\'' || c == '"' || c == '<' || c == '>' || c == ' ') {
                result.append(String.format("\\u%04x", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    private String htmlEntityEncode(String payload) {
        StringBuilder result = new StringBuilder();
        for (char c : payload.toCharArray()) {
            switch (c) {
                case '\'': result.append("&#39;"); break;
                case '"': result.append("&#34;"); break;
                case '<': result.append("&#60;"); break;
                case '>': result.append("&#62;"); break;
                case '&': result.append("&#38;"); break;
                default: result.append(c);
            }
        }
        return result.toString();
    }
    
    private String base64Encode(String payload) {
        return java.util.Base64.getEncoder().encodeToString(payload.getBytes());
    }
    
    private String caseVariation(String payload) {
        StringBuilder result = new StringBuilder();
        Random random = new Random();
        for (char c : payload.toCharArray()) {
            if (Character.isLetter(c)) {
                result.append(random.nextBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    private String commentInjection(String payload) {
        String lower = payload.toLowerCase();
        if (lower.contains("select")) {
            return payload.replaceAll("(?i)select", "SEL/**/ECT");
        }
        if (lower.contains("union")) {
            return payload.replaceAll("(?i)union", "UNI/**/ON");
        }
        if (lower.contains("where")) {
            return payload.replaceAll("(?i)where", "WHE/**/RE");
        }
        return payload;
    }
    
    private String nullByteInjection(String payload) {
        if (payload.startsWith("'") || payload.startsWith("\"")) {
            return payload.substring(0, 1) + "%00" + payload.substring(1);
        }
        return payload;
    }
    
    public void recordAttempt(String techniqueId, boolean success) {
        String key = techniqueId != null ? techniqueId : "unknown";
        
        int currentRate = techniqueSuccessRates.getOrDefault(key, 50);
        int newRate;
        
        if (success) {
            newRate = Math.min(100, currentRate + 5);
        } else {
            newRate = Math.max(0, currentRate - 3);
        }
        
        techniqueSuccessRates.put(key, newRate);
        lastAttemptTimes.put(key, System.currentTimeMillis());
    }
    
    public int getSuccessRate(String techniqueId) {
        return techniqueSuccessRates.getOrDefault(techniqueId, 50);
    }
    
    public long getLastAttemptTime(String techniqueId) {
        return lastAttemptTimes.getOrDefault(techniqueId, 0L);
    }
    
    public List<String> generateBypassPayloads(String originalPayload, String wafId, int maxVariants) {
        List<String> results = new ArrayList<>();
        results.add(originalPayload);
        
        List<BypassTechnique> techniques = getTopStrategies(wafId, 5);
        
        for (BypassTechnique technique : techniques) {
            String bypassed = applyTechnique(originalPayload, technique.getId());
            if (!bypassed.equals(originalPayload) && !results.contains(bypassed)) {
                results.add(bypassed);
                
                if (results.size() >= maxVariants) {
                    break;
                }
            }
        }
        
        return results;
    }
    
    public void addCustomStrategy(String wafId, BypassTechnique technique) {
        List<BypassTechnique> strategies = wafStrategies.computeIfAbsent(wafId, k -> new ArrayList<>());
        if (!strategies.contains(technique)) {
            strategies.add(technique);
        }
    }
    
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("wafCount", wafStrategies.size());
        stats.put("techniqueCount", techniqueSuccessRates.size());
        stats.put("successRates", new HashMap<>(techniqueSuccessRates));
        return stats;
    }
}
