package burp.waf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.concurrent.ConcurrentHashMap;

public class WAFSignature {
    
    private static final Map<String, Pattern> patternCache = new ConcurrentHashMap<>();
    
    private String id;
    private String name;
    private String vendor;
    private WAFType type;
    private List<SignatureRule> rules;
    private List<String> bypassTechniques;
    private int confidence;
    
    private static Pattern getCompiledPattern(String regex) {
        return patternCache.computeIfAbsent(regex, 
            r -> Pattern.compile(r, Pattern.CASE_INSENSITIVE));
    }
    
    public enum WAFType {
        CLOUD,      // 云WAF
        HARDWARE,   // 硬件WAF
        SOFTWARE,   // 软件WAF
        CDN,        // CDN WAF
        UNKNOWN     // 未知类型
    }
    
    public WAFSignature() {
        this.rules = new ArrayList<>();
        this.bypassTechniques = new ArrayList<>();
        this.confidence = 0;
    }
    
    public WAFSignature(String id, String name) {
        this();
        this.id = id;
        this.name = name;
    }
    
    public DetectionResult detect(Map<String, String> headers, String responseBody, int responseCode) {
        int totalScore = 0;
        int matchedRules = 0;
        List<String> matchedDetails = new ArrayList<>();
        
        for (SignatureRule rule : rules) {
            if (rule.matches(headers, responseBody, responseCode)) {
                totalScore += rule.getWeight();
                matchedRules++;
                matchedDetails.add(rule.getDescription());
            }
        }
        
        boolean detected = matchedRules > 0 && totalScore >= 50;
        
        return new DetectionResult(detected, name, vendor, type, totalScore, matchedDetails);
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
    
    public String getVendor() {
        return vendor;
    }
    
    public void setVendor(String vendor) {
        this.vendor = vendor;
    }
    
    public WAFType getType() {
        return type;
    }
    
    public void setType(WAFType type) {
        this.type = type;
    }
    
    public List<SignatureRule> getRules() {
        return new ArrayList<>(rules);
    }
    
    public void setRules(List<SignatureRule> rules) {
        this.rules = rules != null ? new ArrayList<>(rules) : new ArrayList<>();
    }
    
    public void addRule(SignatureRule rule) {
        if (rule != null) {
            rules.add(rule);
        }
    }
    
    public List<String> getBypassTechniques() {
        return new ArrayList<>(bypassTechniques);
    }
    
    public void setBypassTechniques(List<String> bypassTechniques) {
        this.bypassTechniques = bypassTechniques != null ? new ArrayList<>(bypassTechniques) : new ArrayList<>();
    }
    
    public void addBypassTechnique(String technique) {
        if (technique != null && !bypassTechniques.contains(technique)) {
            bypassTechniques.add(technique);
        }
    }
    
    public int getConfidence() {
        return confidence;
    }
    
    public void setConfidence(int confidence) {
        this.confidence = Math.max(0, Math.min(100, confidence));
    }
    
    public static class SignatureRule {
        private String name;
        private String description;
        private String headerPattern;
        private String bodyPattern;
        private Integer statusCode;
        private int weight;
        
        public SignatureRule() {
            this.weight = 10;
        }
        
        public SignatureRule(String name, String description) {
            this();
            this.name = name;
            this.description = description;
        }
        
        public boolean matches(Map<String, String> headers, String responseBody, Integer responseCode) {
            if (statusCode != null && !statusCode.equals(responseCode)) {
                return false;
            }
            
            if (headerPattern != null && headers != null) {
                boolean headerMatched = false;
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    String headerLine = entry.getKey() + ": " + entry.getValue();
                    Pattern pattern = getCompiledPattern(headerPattern);
                    if (pattern.matcher(headerLine).find()) {
                        headerMatched = true;
                        break;
                    }
                }
                if (!headerMatched) {
                    return false;
                }
            }
            
            if (bodyPattern != null && responseBody != null) {
                Pattern pattern = getCompiledPattern(bodyPattern);
                if (!pattern.matcher(responseBody).find()) {
                    return false;
                }
            }
            
            return headerPattern != null || bodyPattern != null || statusCode != null;
        }
        
        public String getName() {
            return name;
        }
        
        public void setName(String name) {
            this.name = name;
        }
        
        public String getDescription() {
            return description;
        }
        
        public void setDescription(String description) {
            this.description = description;
        }
        
        public String getHeaderPattern() {
            return headerPattern;
        }
        
        public void setHeaderPattern(String headerPattern) {
            this.headerPattern = headerPattern;
        }
        
        public String getBodyPattern() {
            return bodyPattern;
        }
        
        public void setBodyPattern(String bodyPattern) {
            this.bodyPattern = bodyPattern;
        }
        
        public Integer getStatusCode() {
            return statusCode;
        }
        
        public void setStatusCode(Integer statusCode) {
            this.statusCode = statusCode;
        }
        
        public int getWeight() {
            return weight;
        }
        
        public void setWeight(int weight) {
            this.weight = weight;
        }
    }
    
    public static class DetectionResult {
        private final boolean detected;
        private final String wafName;
        private final String vendor;
        private final WAFType type;
        private final int score;
        private final List<String> matchedDetails;
        
        public DetectionResult(boolean detected, String wafName, String vendor, WAFType type, int score, List<String> matchedDetails) {
            this.detected = detected;
            this.wafName = wafName;
            this.vendor = vendor;
            this.type = type;
            this.score = score;
            this.matchedDetails = matchedDetails;
        }
        
        public boolean isDetected() {
            return detected;
        }
        
        public String getWafName() {
            return wafName;
        }
        
        public String getVendor() {
            return vendor;
        }
        
        public WAFType getType() {
            return type;
        }
        
        public int getScore() {
            return score;
        }
        
        public List<String> getMatchedDetails() {
            return new ArrayList<>(matchedDetails);
        }
        
        public String getConfidenceLevel() {
            if (score >= 90) return "极高";
            if (score >= 70) return "高";
            if (score >= 50) return "中";
            if (score >= 30) return "低";
            return "极低";
        }
    }
}
