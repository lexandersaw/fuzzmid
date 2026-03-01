package burp.knowledge;

import java.util.List;
import java.util.ArrayList;

public class KnowledgeSearcher {
    
    private final KnowledgeBase knowledgeBase;
    
    public KnowledgeSearcher(KnowledgeBase knowledgeBase) {
        this.knowledgeBase = knowledgeBase;
    }
    
    public List<SuccessfulPayload> search(String keyword) {
        return knowledgeBase.search(keyword);
    }
    
    public List<SuccessfulPayload> searchByVulnType(String vulnType) {
        return knowledgeBase.getByVulnType(vulnType);
    }
    
    public List<SuccessfulPayload> searchByCategory(String category) {
        return knowledgeBase.getByCategory(category);
    }
    
    public List<SuccessfulPayload> searchByTarget(String target) {
        return knowledgeBase.getByTarget(target);
    }
    
    public List<SuccessfulPayload> searchHighSeverity() {
        List<SuccessfulPayload> result = new ArrayList<>();
        for (SuccessfulPayload payload : knowledgeBase.search("")) {
            if (payload.getSeverity() >= 4) {
                result.add(payload);
            }
        }
        return result;
    }
    
    public List<SuccessfulPayload> searchRecent(int count) {
        List<SuccessfulPayload> all = knowledgeBase.search("");
        if (all.size() <= count) return all;
        return all.subList(0, count);
    }
    
    public List<SuccessfulPayload> searchMultipleKeywords(String[] keywords) {
        List<SuccessfulPayload> result = new ArrayList<>();
        for (SuccessfulPayload payload : knowledgeBase.search("")) {
            if (matchesAllKeywords(payload, keywords)) {
                result.add(payload);
            }
        }
        return result;
    }
    
    private boolean matchesAllKeywords(SuccessfulPayload payload, String[] keywords) {
        for (String keyword : keywords) {
            if (!matchesKeyword(payload, keyword.toLowerCase())) {
                return false;
            }
        }
        return true;
    }
    
    private boolean matchesKeyword(SuccessfulPayload payload, String keyword) {
        return (payload.getPayload() != null && payload.getPayload().toLowerCase().contains(keyword)) ||
               (payload.getCategory() != null && payload.getCategory().toLowerCase().contains(keyword)) ||
               (payload.getVulnType() != null && payload.getVulnType().toLowerCase().contains(keyword)) ||
               (payload.getTargetDomain() != null && payload.getTargetDomain().toLowerCase().contains(keyword)) ||
               (payload.getDescription() != null && payload.getDescription().toLowerCase().contains(keyword));
    }
    
    public List<SuccessfulPayload> getSimilarPayloads(SuccessfulPayload reference) {
        List<SuccessfulPayload> result = new ArrayList<>();
        
        for (SuccessfulPayload payload : knowledgeBase.search("")) {
            if (payload.getId().equals(reference.getId())) continue;
            
            int similarity = calculateSimilarity(reference, payload);
            if (similarity >= 2) {
                result.add(payload);
            }
        }
        
        result.sort((a, b) -> 
            Integer.compare(calculateSimilarity(reference, b), calculateSimilarity(reference, a)));
        
        return result.size() > 10 ? result.subList(0, 10) : result;
    }
    
    private int calculateSimilarity(SuccessfulPayload a, SuccessfulPayload b) {
        int score = 0;
        
        if (a.getVulnType() != null && a.getVulnType().equals(b.getVulnType())) {
            score += 3;
        }
        
        if (a.getCategory() != null && a.getCategory().equals(b.getCategory())) {
            score += 2;
        }
        
        if (a.getTargetDomain() != null && a.getTargetDomain().equals(b.getTargetDomain())) {
            score += 2;
        }
        
        if (a.getSeverity() == b.getSeverity()) {
            score += 1;
        }
        
        return score;
    }
}
