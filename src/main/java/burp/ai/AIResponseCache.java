package burp.ai;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.LinkedHashMap;

import org.json.JSONArray;
import org.json.JSONObject;

public class AIResponseCache {
    
    private final String cacheDirPath;
    private final int maxSize;
    private final int expireHours;
    private final Map<String, CacheEntry> cache;
    private final boolean enabled;
    
    public static class CacheEntry {
        private String key;
        private List<String> response;
        private long timestamp;
        private String model;
        private int hitCount;
        
        public CacheEntry(String key, List<String> response, String model) {
            this.key = key;
            this.response = new ArrayList<>(response);
            this.timestamp = System.currentTimeMillis();
            this.model = model;
            this.hitCount = 0;
        }
        
        public String getKey() { return key; }
        public List<String> getResponse() { return new ArrayList<>(response); }
        public long getTimestamp() { return timestamp; }
        public String getModel() { return model; }
        public int getHitCount() { return hitCount; }
        public void incrementHitCount() { hitCount++; }
        
        public boolean isExpired(int expireHours) {
            if (expireHours <= 0) return false;
            long elapsed = System.currentTimeMillis() - timestamp;
            return elapsed > (expireHours * 60 * 60 * 1000L);
        }
        
        public JSONObject toJson() {
            JSONObject json = new JSONObject();
            json.put("key", key);
            json.put("timestamp", timestamp);
            json.put("model", model);
            json.put("hitCount", hitCount);
            
            JSONArray responseArray = new JSONArray();
            for (String item : response) {
                responseArray.put(item);
            }
            json.put("response", responseArray);
            
            return json;
        }
        
        public static CacheEntry fromJson(JSONObject json) {
            if (json == null) return null;
            
            String key = json.optString("key", "");
            String model = json.optString("model", "");
            long timestamp = json.optLong("timestamp", System.currentTimeMillis());
            int hitCount = json.optInt("hitCount", 0);
            
            List<String> response = new ArrayList<>();
            JSONArray responseArray = json.optJSONArray("response");
            if (responseArray != null) {
                for (int i = 0; i < responseArray.length(); i++) {
                    response.add(responseArray.optString(i, ""));
                }
            }
            
            CacheEntry entry = new CacheEntry(key, response, model);
            entry.timestamp = timestamp;
            entry.hitCount = hitCount;
            return entry;
        }
    }
    
    public AIResponseCache() {
        this(true, 100, 24);
    }
    
    public AIResponseCache(boolean enabled, int maxSize, int expireHours) {
        this.enabled = enabled;
        this.maxSize = maxSize;
        this.expireHours = expireHours;
        this.cacheDirPath = System.getProperty("user.home") + "/.config/fuzzMind/cache";
        this.cache = new LinkedHashMap<>();
        
        if (enabled) {
            createCacheDir();
            loadCache();
            cleanExpiredEntries();
        }
    }
    
    private void createCacheDir() {
        File cacheDir = new File(cacheDirPath);
        if (!cacheDir.exists()) {
            cacheDir.mkdirs();
        }
    }
    
    private String generateKey(String systemPrompt, String userPrompt) {
        try {
            String combined = (systemPrompt != null ? systemPrompt : "") + "|" + (userPrompt != null ? userPrompt : "");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(combined.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf((systemPrompt + "|" + userPrompt).hashCode());
        }
    }
    
    public List<String> get(String systemPrompt, String userPrompt) {
        if (!enabled) return null;
        
        String key = generateKey(systemPrompt, userPrompt);
        CacheEntry entry = cache.get(key);
        
        if (entry != null) {
            if (entry.isExpired(expireHours)) {
                cache.remove(key);
                deleteCacheFile(key);
                return null;
            }
            
            entry.incrementHitCount();
            saveCacheFile(entry);
            return entry.getResponse();
        }
        
        return null;
    }
    
    public void put(String systemPrompt, String userPrompt, List<String> response, String model) {
        if (!enabled || response == null || response.isEmpty()) return;
        
        String key = generateKey(systemPrompt, userPrompt);
        CacheEntry entry = new CacheEntry(key, response, model);
        
        if (cache.size() >= maxSize) {
            evictLRU();
        }
        
        cache.put(key, entry);
        saveCacheFile(entry);
    }
    
    public boolean contains(String systemPrompt, String userPrompt) {
        if (!enabled) return false;
        
        String key = generateKey(systemPrompt, userPrompt);
        CacheEntry entry = cache.get(key);
        
        if (entry != null && !entry.isExpired(expireHours)) {
            return true;
        }
        
        return false;
    }
    
    public void remove(String systemPrompt, String userPrompt) {
        String key = generateKey(systemPrompt, userPrompt);
        cache.remove(key);
        deleteCacheFile(key);
    }
    
    public void clear() {
        cache.clear();
        File cacheDir = new File(cacheDirPath);
        if (cacheDir.exists() && cacheDir.isDirectory()) {
            File[] files = cacheDir.listFiles((dir, name) -> name.endsWith(".json"));
            if (files != null) {
                for (File file : files) {
                    file.delete();
                }
            }
        }
    }
    
    public int size() {
        return cache.size();
    }
    
    public int getMaxSize() {
        return maxSize;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", enabled);
        stats.put("size", cache.size());
        stats.put("maxSize", maxSize);
        stats.put("expireHours", expireHours);
        
        long totalHits = 0;
        for (CacheEntry entry : cache.values()) {
            totalHits += entry.getHitCount();
        }
        stats.put("totalHits", totalHits);
        
        return stats;
    }
    
    private void evictLRU() {
        String oldestKey = null;
        long oldestTime = Long.MAX_VALUE;
        int lowestHits = Integer.MAX_VALUE;
        
        for (Map.Entry<String, CacheEntry> entry : cache.entrySet()) {
            CacheEntry ce = entry.getValue();
            if (ce.getHitCount() < lowestHits || 
                (ce.getHitCount() == lowestHits && ce.getTimestamp() < oldestTime)) {
                lowestHits = ce.getHitCount();
                oldestTime = ce.getTimestamp();
                oldestKey = entry.getKey();
            }
        }
        
        if (oldestKey != null) {
            cache.remove(oldestKey);
            deleteCacheFile(oldestKey);
        }
    }
    
    private void cleanExpiredEntries() {
        List<String> keysToRemove = new ArrayList<>();
        
        for (Map.Entry<String, CacheEntry> entry : cache.entrySet()) {
            if (entry.getValue().isExpired(expireHours)) {
                keysToRemove.add(entry.getKey());
            }
        }
        
        for (String key : keysToRemove) {
            cache.remove(key);
            deleteCacheFile(key);
        }
    }
    
    private void loadCache() {
        File cacheDir = new File(cacheDirPath);
        if (!cacheDir.exists() || !cacheDir.isDirectory()) {
            return;
        }
        
        File[] files = cacheDir.listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null) return;
        
        for (File file : files) {
            try {
                String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
                JSONObject json = new JSONObject(content);
                CacheEntry entry = CacheEntry.fromJson(json);
                
                if (entry != null && !entry.isExpired(expireHours)) {
                    cache.put(entry.getKey(), entry);
                } else if (entry != null) {
                    file.delete();
                }
            } catch (Exception e) {
                System.err.println("Failed to load cache file: " + file.getName());
            }
        }
    }
    
    private void saveCacheFile(CacheEntry entry) {
        try {
            String filePath = cacheDirPath + "/" + entry.getKey() + ".json";
            JSONObject json = entry.toJson();
            String jsonStr = json.toString(2);
            Files.write(Paths.get(filePath), jsonStr.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.err.println("Failed to save cache file: " + e.getMessage());
        }
    }
    
    private void deleteCacheFile(String key) {
        String filePath = cacheDirPath + "/" + key + ".json";
        new File(filePath).delete();
    }
}
