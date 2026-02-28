package burp.dictionary;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

public class HistoryManager {
    
    private final String historyDirPath;
    private final int maxHistoryEntries;
    private final Map<String, HistoryEntry> history;
    
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
            this.dictionaryName = dictionaryName;
            this.promptType = promptType;
            this.prompt = prompt;
            this.generatedPayloads = new ArrayList<>(generatedPayloads);
            this.timestamp = System.currentTimeMillis();
            this.payloadCount = generatedPayloads.size();
            this.model = model;
            this.baseUrl = baseUrl;
        }
        
        public String getId() { return id; }
        public String getDictionaryName() { return dictionaryName; }
        public String getPromptType() { return promptType; }
        public String getPrompt() { return prompt; }
        public List<String> getGeneratedPayloads() { return generatedPayloads; }
        public long getTimestamp() { return timestamp; }
        public int getPayloadCount() { return payloadCount; }
        public String getModel() { return model; }
        public String getBaseUrl() { return baseUrl; }
        
        public String getFormattedTime() {
            return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(timestamp));
        }
    }
    
    public HistoryManager() {
        this.historyDirPath = System.getProperty("user.home") + "/.config/fuzzMind/history";
        this.maxHistoryEntries = 100;
        this.history = new LinkedHashMap<>();
        
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
        
        history.put(entry.getId(), entry);
        
        if (history.size() > maxHistoryEntries) {
            String oldestKey = history.keySet().iterator().next();
            history.remove(oldestKey);
            deleteHistoryFile(oldestKey);
        }
        
        saveHistoryEntry(entry);
    }
    
    public HistoryEntry getHistoryEntry(String id) {
        return history.get(id);
    }
    
    public List<HistoryEntry> getAllHistoryEntries() {
        return new ArrayList<>(history.values());
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
        history.remove(id);
        deleteHistoryFile(id);
    }
    
    public void clearHistory() {
        history.clear();
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
            
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"id\": \"").append(entry.getId()).append("\",\n");
            json.append("  \"dictionaryName\": \"").append(escapeJson(entry.getDictionaryName())).append("\",\n");
            json.append("  \"promptType\": \"").append(escapeJson(entry.getPromptType())).append("\",\n");
            json.append("  \"prompt\": \"").append(escapeJson(entry.getPrompt())).append("\",\n");
            json.append("  \"timestamp\": ").append(entry.getTimestamp()).append(",\n");
            json.append("  \"payloadCount\": ").append(entry.getPayloadCount()).append(",\n");
            json.append("  \"model\": \"").append(escapeJson(entry.getModel())).append("\",\n");
            json.append("  \"baseUrl\": \"").append(escapeJson(entry.getBaseUrl())).append("\",\n");
            json.append("  \"payloads\": [\n");
            
            List<String> payloads = entry.getGeneratedPayloads();
            for (int i = 0; i < payloads.size(); i++) {
                json.append("    \"").append(escapeJson(payloads.get(i))).append("\"");
                if (i < payloads.size() - 1) {
                    json.append(",");
                }
                json.append("\n");
            }
            
            json.append("  ]\n");
            json.append("}");
            
            Files.write(Paths.get(filePath), json.toString().getBytes(StandardCharsets.UTF_8));
            
        } catch (IOException e) {
            e.printStackTrace();
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
        
        for (File file : files) {
            try {
                HistoryEntry entry = parseHistoryFile(file);
                if (entry != null) {
                    history.put(entry.getId(), entry);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        List<HistoryEntry> sorted = history.values().stream()
                .sorted(Comparator.comparingLong(HistoryEntry::getTimestamp))
                .collect(Collectors.toList());
        
        history.clear();
        for (HistoryEntry entry : sorted) {
            history.put(entry.getId(), entry);
        }
    }
    
    private HistoryEntry parseHistoryFile(File file) throws IOException {
        String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        
        String id = extractJsonString(content, "id");
        String dictionaryName = extractJsonString(content, "dictionaryName");
        String promptType = extractJsonString(content, "promptType");
        String prompt = extractJsonString(content, "prompt");
        long timestamp = extractJsonLong(content, "timestamp");
        int payloadCount = extractJsonInt(content, "payloadCount");
        String model = extractJsonString(content, "model");
        String baseUrl = extractJsonString(content, "baseUrl");
        
        List<String> payloads = extractJsonArray(content, "payloads");
        
        HistoryEntry entry = new HistoryEntry(dictionaryName, promptType, prompt, payloads, model, baseUrl);
        
        return entry;
    }
    
    private String extractJsonString(String content, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(content);
        return m.find() ? unescapeJson(m.group(1)) : "";
    }
    
    private long extractJsonLong(String content, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*(\\d+)";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(content);
        return m.find() ? Long.parseLong(m.group(1)) : 0;
    }
    
    private int extractJsonInt(String content, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*(\\d+)";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(content);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }
    
    private List<String> extractJsonArray(String content, String key) {
        List<String> result = new ArrayList<>();
        
        String pattern = "\"" + key + "\"\\s*:\\s*\\[([^\\]]*)\\]";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern, java.util.regex.Pattern.DOTALL);
        java.util.regex.Matcher m = p.matcher(content);
        
        if (m.find()) {
            String arrayContent = m.group(1);
            java.util.regex.Pattern itemPattern = java.util.regex.Pattern.compile("\"([^\"]*)\"");
            java.util.regex.Matcher itemMatcher = itemPattern.matcher(arrayContent);
            
            while (itemMatcher.find()) {
                result.add(unescapeJson(itemMatcher.group(1)));
            }
        }
        
        return result;
    }
    
    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
    
    private String unescapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t");
    }
}
