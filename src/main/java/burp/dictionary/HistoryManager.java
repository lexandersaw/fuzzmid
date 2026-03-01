package burp.dictionary;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONObject;

public class HistoryManager {
    
    private final String historyDirPath;
    private final int maxHistoryEntries;
    private final ConcurrentHashMap<String, HistoryEntry> history;
    private final ConcurrentLinkedQueue<String> insertionOrder;
    private final Object historyLock = new Object();
    
    public static class HistoryEntry {
        private String id;
        private String dictionaryName;
        private String promptType;
        private String prompt;
        private List<String> generatedPayloads;
        private long timestamp;
        private int payloadCount;
        private String model;
        private String baseUrl;
        
        public HistoryEntry(String dictionaryName, String promptType, String prompt, 
                           List<String> generatedPayloads, String model, String baseUrl) {
            this.id = UUID.randomUUID().toString().substring(0, 8);
            this.dictionaryName = dictionaryName != null ? dictionaryName : "";
            this.promptType = promptType != null ? promptType : "";
            this.prompt = prompt != null ? prompt : "";
            this.generatedPayloads = generatedPayloads != null ? new ArrayList<>(generatedPayloads) : new ArrayList<>();
            this.timestamp = System.currentTimeMillis();
            this.payloadCount = this.generatedPayloads.size();
            this.model = model != null ? model : "";
            this.baseUrl = baseUrl != null ? baseUrl : "";
        }
        
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getDictionaryName() { return dictionaryName; }
        public String getPromptType() { return promptType; }
        public String getPrompt() { return prompt; }
        public List<String> getGeneratedPayloads() { return generatedPayloads; }
        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
        public int getPayloadCount() { return payloadCount; }
        public String getModel() { return model; }
        public String getBaseUrl() { return baseUrl; }
        
        public String getFormattedTime() {
            return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(timestamp));
        }
        
        public JSONObject toJson() {
            JSONObject json = new JSONObject();
            json.put("id", id);
            json.put("dictionaryName", dictionaryName);
            json.put("promptType", promptType);
            json.put("prompt", prompt);
            json.put("timestamp", timestamp);
            json.put("payloadCount", payloadCount);
            json.put("model", model);
            json.put("baseUrl", baseUrl);
            
            JSONArray payloadsArray = new JSONArray();
            for (String payload : generatedPayloads) {
                payloadsArray.put(payload);
            }
            json.put("payloads", payloadsArray);
            
            return json;
        }
        
        public static HistoryEntry fromJson(JSONObject json) {
            if (json == null) return null;
            
            String id = json.optString("id", "");
            String dictionaryName = json.optString("dictionaryName", "");
            String promptType = json.optString("promptType", "");
            String prompt = json.optString("prompt", "");
            long timestamp = json.optLong("timestamp", System.currentTimeMillis());
            String model = json.optString("model", "");
            String baseUrl = json.optString("baseUrl", "");
            
            List<String> payloads = new ArrayList<>();
            JSONArray payloadsArray = json.optJSONArray("payloads");
            if (payloadsArray != null) {
                for (int i = 0; i < payloadsArray.length(); i++) {
                    String payload = payloadsArray.optString(i, "");
                    if (!payload.isEmpty()) {
                        payloads.add(payload);
                    }
                }
            }
            
            HistoryEntry entry = new HistoryEntry(dictionaryName, promptType, prompt, payloads, model, baseUrl);
            entry.setId(id);
            entry.setTimestamp(timestamp);
            return entry;
        }
    }
    
    public HistoryManager() {
        this.historyDirPath = System.getProperty("user.home") + "/.config/fuzzMind/history";
        this.maxHistoryEntries = 100;
        this.history = new ConcurrentHashMap<>();
        this.insertionOrder = new ConcurrentLinkedQueue<>();
        
        createHistoryDir();
        loadHistory();
    }
    
    private void createHistoryDir() {
        File historyDir = new File(historyDirPath);
        if (!historyDir.exists()) {
            historyDir.mkdirs();
        }
    }
    
    public void addHistoryEntry(String dictionaryName, String promptType, String prompt,
                                List<String> generatedPayloads, String model, String baseUrl) {
        HistoryEntry entry = new HistoryEntry(dictionaryName, promptType, prompt, 
                                              generatedPayloads, model, baseUrl);
        
        synchronized (historyLock) {
            history.put(entry.getId(), entry);
            insertionOrder.add(entry.getId());
            
            if (history.size() > maxHistoryEntries) {
                String oldestKey = insertionOrder.poll();
                if (oldestKey != null) {
                    history.remove(oldestKey);
                    deleteHistoryFile(oldestKey);
                }
            }
        }
        
        saveHistoryEntry(entry);
    }
    
    public HistoryEntry getHistoryEntry(String id) {
        return history.get(id);
    }
    
    public List<HistoryEntry> getAllHistoryEntries() {
        synchronized (historyLock) {
            List<HistoryEntry> entries = new ArrayList<>();
            for (String key : insertionOrder) {
                HistoryEntry entry = history.get(key);
                if (entry != null) {
                    entries.add(entry);
                }
            }
            return entries;
        }
    }
    
    public List<HistoryEntry> getHistoryByType(String promptType) {
        return history.values().stream()
                .filter(e -> e.getPromptType().equals(promptType))
                .collect(Collectors.toList());
    }
    
    public List<HistoryEntry> getRecentHistory(int count) {
        List<HistoryEntry> entries = new ArrayList<>(history.values());
        int start = Math.max(0, entries.size() - count);
        return entries.subList(start, entries.size());
    }
    
    public void deleteHistoryEntry(String id) {
        synchronized (historyLock) {
            history.remove(id);
            insertionOrder.remove(id);
        }
        deleteHistoryFile(id);
    }
    
    public void clearHistory() {
        synchronized (historyLock) {
            history.clear();
            insertionOrder.clear();
        }
        File historyDir = new File(historyDirPath);
        if (historyDir.exists() && historyDir.isDirectory()) {
            File[] files = historyDir.listFiles((dir, name) -> name.endsWith(".json"));
            if (files != null) {
                for (File file : files) {
                    file.delete();
                }
            }
        }
    }
    
    private void saveHistoryEntry(HistoryEntry entry) {
        try {
            String filePath = historyDirPath + "/" + entry.getId() + ".json";
            
            JSONObject json = entry.toJson();
            String jsonStr = json.toString(2);
            
            Files.write(Paths.get(filePath), jsonStr.getBytes(StandardCharsets.UTF_8));
            
        } catch (IOException e) {
            System.err.println("Failed to save history file: " + e.getMessage());
        }
    }
    
    private void deleteHistoryFile(String id) {
        String filePath = historyDirPath + "/" + id + ".json";
        new File(filePath).delete();
    }
    
    private void loadHistory() {
        File historyDir = new File(historyDirPath);
        if (!historyDir.exists() || !historyDir.isDirectory()) {
            return;
        }
        
        File[] files = historyDir.listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null) {
            return;
        }
        
        List<HistoryEntry> tempList = new ArrayList<>();
        for (File file : files) {
            try {
                HistoryEntry entry = parseHistoryFile(file);
                if (entry != null && entry.getId() != null && !entry.getId().isEmpty()) {
                    tempList.add(entry);
                }
            } catch (Exception e) {
                System.err.println("Failed to parse history file: " + file.getName() + " - " + e.getMessage());
            }
        }
        
        tempList.sort(Comparator.comparingLong(HistoryEntry::getTimestamp));
        
        synchronized (historyLock) {
            history.clear();
            insertionOrder.clear();
            for (HistoryEntry entry : tempList) {
                history.put(entry.getId(), entry);
                insertionOrder.add(entry.getId());
            }
        }
    }
    
    private HistoryEntry parseHistoryFile(File file) throws IOException {
        try {
            String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
            
            if (content == null || content.trim().isEmpty()) {
                return null;
            }
            
            JSONObject json = new JSONObject(content);
            return HistoryEntry.fromJson(json);
            
        } catch (Exception e) {
            System.err.println("JSON parse error for file " + file.getName() + ": " + e.getMessage());
            
            if (file.exists()) {
                String backupPath = file.getAbsolutePath() + ".bak";
                try {
                    Files.copy(file.toPath(), Paths.get(backupPath));
                    System.err.println("Backed up corrupted file to: " + backupPath);
                } catch (IOException ioe) {
                    System.err.println("Failed to backup corrupted file: " + ioe.getMessage());
                }
            }
            
            return null;
        }
    }
}
