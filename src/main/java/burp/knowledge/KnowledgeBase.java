package burp.knowledge;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.json.*;

import burp.AppConfig;

public class KnowledgeBase {
    
    private static final String KNOWLEDGE_DIR = 
        System.getProperty("user.home") + "/" + AppConfig.CONFIG_DIR_NAME + "/knowledge";
    private static final String PAYLOADS_FILE = KNOWLEDGE_DIR + "/payloads.json";
    private static final int MAX_ENTRIES = 1000;
    
    private final Map<String, SuccessfulPayload> payloads;
    private final Map<String, Set<String>> categoryIndex;
    private final Map<String, Set<String>> vulnTypeIndex;
    private final Map<String, Set<String>> targetIndex;
    
    public KnowledgeBase() {
        this.payloads = new ConcurrentHashMap<>();
        this.categoryIndex = new ConcurrentHashMap<>();
        this.vulnTypeIndex = new ConcurrentHashMap<>();
        this.targetIndex = new ConcurrentHashMap<>();
        loadKnowledge();
    }
    
    public void addSuccessfulPayload(SuccessfulPayload payload) {
        if (payload == null || payload.getPayload() == null) return;
        
        String id = payload.getId();
        if (id == null || id.isEmpty()) {
            id = generateId();
            payload.setId(id);
        }
        
        if (payloads.size() >= MAX_ENTRIES) {
            evictOldest();
        }
        
        payloads.put(id, payload);
        
        addToIndex(categoryIndex, payload.getCategory(), id);
        addToIndex(vulnTypeIndex, payload.getVulnType(), id);
        addToIndex(targetIndex, payload.getTargetDomain(), id);
        
        saveKnowledge();
    }
    
    private String generateId() {
        return UUID.randomUUID().toString().substring(0, 12);
    }
    
    private void evictOldest() {
        Optional<SuccessfulPayload> oldest = payloads.values().stream()
            .min(Comparator.comparingLong(SuccessfulPayload::getTimestamp));
        
        if (oldest.isPresent()) {
            String id = oldest.get().getId();
            removePayload(id);
        }
    }
    
    private void removePayload(String id) {
        SuccessfulPayload payload = payloads.remove(id);
        if (payload != null) {
            removeFromIndex(categoryIndex, payload.getCategory(), id);
            removeFromIndex(vulnTypeIndex, payload.getVulnType(), id);
            removeFromIndex(targetIndex, payload.getTargetDomain(), id);
        }
    }
    
    private void addToIndex(Map<String, Set<String>> index, String key, String id) {
        if (key == null || key.isEmpty()) return;
        index.computeIfAbsent(key.toLowerCase(), k -> ConcurrentHashMap.newKeySet()).add(id);
    }
    
    private void removeFromIndex(Map<String, Set<String>> index, String key, String id) {
        if (key == null || key.isEmpty()) return;
        Set<String> ids = index.get(key.toLowerCase());
        if (ids != null) {
            ids.remove(id);
            if (ids.isEmpty()) {
                index.remove(key.toLowerCase());
            }
        }
    }
    
    public List<SuccessfulPayload> search(String keyword) {
        if (keyword == null || keyword.trim().isEmpty()) {
            return new ArrayList<>(payloads.values());
        }
        
        String keywordLower = keyword.toLowerCase();
        
        return payloads.values().stream()
            .filter(p -> matchesKeyword(p, keywordLower))
            .sorted(Comparator.comparingLong(SuccessfulPayload::getTimestamp).reversed())
            .collect(Collectors.toList());
    }
    
    private boolean matchesKeyword(SuccessfulPayload payload, String keyword) {
        return (payload.getPayload() != null && payload.getPayload().toLowerCase().contains(keyword)) ||
               (payload.getCategory() != null && payload.getCategory().toLowerCase().contains(keyword)) ||
               (payload.getVulnType() != null && payload.getVulnType().toLowerCase().contains(keyword)) ||
               (payload.getTargetDomain() != null && payload.getTargetDomain().toLowerCase().contains(keyword)) ||
               (payload.getDescription() != null && payload.getDescription().toLowerCase().contains(keyword));
    }
    
    public List<SuccessfulPayload> getByCategory(String category) {
        if (category == null) return new ArrayList<>();
        Set<String> ids = categoryIndex.get(category.toLowerCase());
        if (ids == null) return new ArrayList<>();
        
        return ids.stream()
            .map(payloads::get)
            .filter(Objects::nonNull)
            .sorted(Comparator.comparingLong(SuccessfulPayload::getTimestamp).reversed())
            .collect(Collectors.toList());
    }
    
    public List<SuccessfulPayload> getByVulnType(String vulnType) {
        if (vulnType == null) return new ArrayList<>();
        Set<String> ids = vulnTypeIndex.get(vulnType.toLowerCase());
        if (ids == null) return new ArrayList<>();
        
        return ids.stream()
            .map(payloads::get)
            .filter(Objects::nonNull)
            .sorted(Comparator.comparingLong(SuccessfulPayload::getTimestamp).reversed())
            .collect(Collectors.toList());
    }
    
    public List<SuccessfulPayload> getByTarget(String target) {
        if (target == null) return new ArrayList<>();
        Set<String> ids = targetIndex.get(target.toLowerCase());
        if (ids == null) return new ArrayList<>();
        
        return ids.stream()
            .map(payloads::get)
            .filter(Objects::nonNull)
            .sorted(Comparator.comparingLong(SuccessfulPayload::getTimestamp).reversed())
            .collect(Collectors.toList());
    }
    
    public List<String> getCategories() {
        return new ArrayList<>(categoryIndex.keySet());
    }
    
    public List<String> getVulnTypes() {
        return new ArrayList<>(vulnTypeIndex.keySet());
    }
    
    public List<String> getTargets() {
        return new ArrayList<>(targetIndex.keySet());
    }
    
    public int size() {
        return payloads.size();
    }
    
    public void clear() {
        payloads.clear();
        categoryIndex.clear();
        vulnTypeIndex.clear();
        targetIndex.clear();
        saveKnowledge();
    }
    
    private void loadKnowledge() {
        File file = new File(PAYLOADS_FILE);
        if (!file.exists()) return;
        
        try {
            String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
            JSONArray array = new JSONArray(content);
            
            for (int i = 0; i < array.length(); i++) {
                JSONObject json = array.getJSONObject(i);
                SuccessfulPayload payload = SuccessfulPayload.fromJson(json);
                if (payload != null && payload.getId() != null) {
                    payloads.put(payload.getId(), payload);
                    addToIndex(categoryIndex, payload.getCategory(), payload.getId());
                    addToIndex(vulnTypeIndex, payload.getVulnType(), payload.getId());
                    addToIndex(targetIndex, payload.getTargetDomain(), payload.getId());
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load knowledge base: " + e.getMessage());
        }
    }
    
    private void saveKnowledge() {
        try {
            File dir = new File(KNOWLEDGE_DIR);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            
            JSONArray array = new JSONArray();
            for (SuccessfulPayload payload : payloads.values()) {
                array.put(payload.toJson());
            }
            
            String jsonStr = array.toString(2);
            Files.write(Paths.get(PAYLOADS_FILE), jsonStr.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.err.println("Failed to save knowledge base: " + e.getMessage());
        }
    }
    
    public void exportToFile(String filePath) throws IOException {
        JSONArray array = new JSONArray();
        for (SuccessfulPayload payload : payloads.values()) {
            array.put(payload.toJson());
        }
        Files.write(Paths.get(filePath), array.toString(2).getBytes(StandardCharsets.UTF_8));
    }
    
    public void importFromFile(String filePath) throws IOException {
        String content = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
        JSONArray array = new JSONArray(content);
        
        for (int i = 0; i < array.length(); i++) {
            JSONObject json = array.getJSONObject(i);
            SuccessfulPayload payload = SuccessfulPayload.fromJson(json);
            if (payload != null) {
                addSuccessfulPayload(payload);
            }
        }
    }
    
    public KnowledgeStatistics getStatistics() {
        return new KnowledgeStatistics(
            payloads.size(),
            categoryIndex.size(),
            vulnTypeIndex.size(),
            targetIndex.size()
        );
    }
    
    public static class KnowledgeStatistics {
        private final int totalPayloads;
        private final int categoryCount;
        private final int vulnTypeCount;
        private final int targetCount;
        
        public KnowledgeStatistics(int totalPayloads, int categoryCount,
                                  int vulnTypeCount, int targetCount) {
            this.totalPayloads = totalPayloads;
            this.categoryCount = categoryCount;
            this.vulnTypeCount = vulnTypeCount;
            this.targetCount = targetCount;
        }
        
        public int getTotalPayloads() { return totalPayloads; }
        public int getCategoryCount() { return categoryCount; }
        public int getVulnTypeCount() { return vulnTypeCount; }
        public int getTargetCount() { return targetCount; }
    }
}
