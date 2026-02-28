package burp.dictionary;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import burp.ConfigManager;

public class EnhancedDictionaryManager {
    
    private final Map<String, DictionaryEntry> generatedDictionaries;
    private final Map<String, DictionaryEntry> savedDictionaries;
    private String selectedDictionaryName;
    private DictionaryType selectedDictionaryType;
    private final String configDirPath;
    
    public enum DictionaryType {
        GENERATED,
        SAVED
    }
    
    public static class DictionaryEntry {
        private String name;
        private List<String> entries;
        private DictionaryStatistics statistics;
        private Set<String> tags;
        private long createdTime;
        private long modifiedTime;
        private String description;
        
        public DictionaryEntry(String name, List<String> entries) {
            this.name = name;
            this.entries = new ArrayList<>(entries);
            this.tags = new HashSet<>();
            this.createdTime = System.currentTimeMillis();
            this.modifiedTime = this.createdTime;
            this.statistics = calculateStatistics(entries);
        }
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public List<String> getEntries() { return entries; }
        public void setEntries(List<String> entries) { 
            this.entries = new ArrayList<>(entries);
            this.statistics = calculateStatistics(entries);
            this.modifiedTime = System.currentTimeMillis();
        }
        public DictionaryStatistics getStatistics() { return statistics; }
        public Set<String> getTags() { return tags; }
        public void setTags(Set<String> tags) { this.tags = new HashSet<>(tags); }
        public void addTag(String tag) { this.tags.add(tag); }
        public void removeTag(String tag) { this.tags.remove(tag); }
        public long getCreatedTime() { return createdTime; }
        public long getModifiedTime() { return modifiedTime; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
    }
    
    public static class DictionaryStatistics {
        private int totalCount;
        private int uniqueCount;
        private int minLength;
        private int maxLength;
        private double avgLength;
        private Map<Integer, Integer> lengthDistribution;
        private Map<Character, Integer> firstCharDistribution;
        
        public int getTotalCount() { return totalCount; }
        public void setTotalCount(int totalCount) { this.totalCount = totalCount; }
        public int getUniqueCount() { return uniqueCount; }
        public void setUniqueCount(int uniqueCount) { this.uniqueCount = uniqueCount; }
        public int getMinLength() { return minLength; }
        public void setMinLength(int minLength) { this.minLength = minLength; }
        public int getMaxLength() { return maxLength; }
        public void setMaxLength(int maxLength) { this.maxLength = maxLength; }
        public double getAvgLength() { return avgLength; }
        public void setAvgLength(double avgLength) { this.avgLength = avgLength; }
        public Map<Integer, Integer> getLengthDistribution() { return lengthDistribution; }
        public void setLengthDistribution(Map<Integer, Integer> lengthDistribution) { this.lengthDistribution = lengthDistribution; }
        public Map<Character, Integer> getFirstCharDistribution() { return firstCharDistribution; }
        public void setFirstCharDistribution(Map<Character, Integer> firstCharDistribution) { this.firstCharDistribution = firstCharDistribution; }
        
        @Override
        public String toString() {
            return String.format(
                "统计信息:\n" +
                "  总条目: %d\n" +
                "  唯一条目: %d\n" +
                "  长度范围: %d - %d\n" +
                "  平均长度: %.2f",
                totalCount, uniqueCount, minLength, maxLength, avgLength
            );
        }
    }
    
    private static DictionaryStatistics calculateStatistics(List<String> entries) {
        DictionaryStatistics stats = new DictionaryStatistics();
        
        if (entries == null || entries.isEmpty()) {
            stats.setTotalCount(0);
            stats.setUniqueCount(0);
            stats.setMinLength(0);
            stats.setMaxLength(0);
            stats.setAvgLength(0);
            stats.setLengthDistribution(new HashMap<>());
            stats.firstCharDistribution = new HashMap<>();
            return stats;
        }
        
        stats.setTotalCount(entries.size());
        stats.setUniqueCount(new HashSet<>(entries).size());
        
        int min = Integer.MAX_VALUE;
        int max = Integer.MIN_VALUE;
        int totalLength = 0;
        Map<Integer, Integer> lengthDist = new HashMap<>();
        Map<Character, Integer> firstCharDist = new HashMap<>();
        
        for (String entry : entries) {
            int len = entry.length();
            min = Math.min(min, len);
            max = Math.max(max, len);
            totalLength += len;
            
            lengthDist.merge(len, 1, Integer::sum);
            
            if (!entry.isEmpty()) {
                char firstChar = Character.toLowerCase(entry.charAt(0));
                firstCharDist.merge(firstChar, 1, Integer::sum);
            }
        }
        
        stats.setMinLength(min == Integer.MAX_VALUE ? 0 : min);
        stats.setMaxLength(max == Integer.MIN_VALUE ? 0 : max);
        stats.setAvgLength((double) totalLength / entries.size());
        stats.setLengthDistribution(lengthDist);
        stats.firstCharDistribution = firstCharDist;
        
        return stats;
    }
    
    public EnhancedDictionaryManager() {
        this.generatedDictionaries = new LinkedHashMap<>();
        this.savedDictionaries = new LinkedHashMap<>();
        this.selectedDictionaryName = null;
        this.selectedDictionaryType = DictionaryType.GENERATED;
        this.configDirPath = System.getProperty("user.home") + "/.config/fuzzMind";
        
        createConfigDir();
    }
    
    private void createConfigDir() {
        File configDir = new File(configDirPath);
        if (!configDir.exists()) {
            configDir.mkdirs();
        }
    }
    
    public void addDictionary(String name, List<String> entries) {
        DictionaryEntry entry = new DictionaryEntry(name, entries);
        generatedDictionaries.put(name, entry);
        
        if (selectedDictionaryName == null) {
            selectedDictionaryName = name;
            selectedDictionaryType = DictionaryType.GENERATED;
        }
    }
    
    public void updateDictionary(String name, List<String> entries) {
        DictionaryEntry entry = generatedDictionaries.get(name);
        if (entry != null) {
            entry.setEntries(entries);
        }
    }
    
    public DictionaryEntry getDictionaryEntry(String name, DictionaryType type) {
        if (type == DictionaryType.GENERATED) {
            return generatedDictionaries.get(name);
        } else {
            return savedDictionaries.get(name);
        }
    }
    
    public List<String> getDictionary(String name, DictionaryType type) {
        DictionaryEntry entry = getDictionaryEntry(name, type);
        return entry != null ? entry.getEntries() : new ArrayList<>();
    }
    
    public List<String> getDictionary(String name) {
        return getDictionary(name, DictionaryType.GENERATED);
    }
    
    public List<String> getSelectedDictionary() {
        if (selectedDictionaryName == null) {
            return new ArrayList<>();
        }
        return getDictionary(selectedDictionaryName, selectedDictionaryType);
    }
    
    public DictionaryEntry getSelectedDictionaryEntry() {
        if (selectedDictionaryName == null) {
            return null;
        }
        return getDictionaryEntry(selectedDictionaryName, selectedDictionaryType);
    }
    
    public void setSelectedDictionary(String name, DictionaryType type) {
        if ((type == DictionaryType.GENERATED && generatedDictionaries.containsKey(name)) ||
            (type == DictionaryType.SAVED && savedDictionaries.containsKey(name))) {
            selectedDictionaryName = name;
            selectedDictionaryType = type;
        }
    }
    
    public void setSelectedDictionary(String name) {
        setSelectedDictionary(name, DictionaryType.GENERATED);
    }
    
    public String getSelectedDictionaryName() { return selectedDictionaryName; }
    public DictionaryType getSelectedDictionaryType() { return selectedDictionaryType; }
    
    public List<String> getGeneratedDictionaryNames() {
        return new ArrayList<>(generatedDictionaries.keySet());
    }
    
    public List<String> getSavedDictionaryNames() {
        return new ArrayList<>(savedDictionaries.keySet());
    }
    
    public void removeDictionary(String name) {
        generatedDictionaries.remove(name);
        updateSelectedDictionary(name, DictionaryType.GENERATED);
    }
    
    public void removeSavedDictionary(String name) {
        savedDictionaries.remove(name);
        
        String fileName = configDirPath + "/" + name + ".txt";
        new File(fileName).delete();
        
        updateSelectedDictionary(name, DictionaryType.SAVED);
    }
    
    private void updateSelectedDictionary(String removedName, DictionaryType removedType) {
        if (removedName.equals(selectedDictionaryName) && selectedDictionaryType == removedType) {
            if (!generatedDictionaries.isEmpty()) {
                selectedDictionaryName = generatedDictionaries.keySet().iterator().next();
                selectedDictionaryType = DictionaryType.GENERATED;
            } else if (!savedDictionaries.isEmpty()) {
                selectedDictionaryName = savedDictionaries.keySet().iterator().next();
                selectedDictionaryType = DictionaryType.SAVED;
            } else {
                selectedDictionaryName = null;
            }
        }
    }
    
    public int mergeDictionaries(List<String> names, String newName, DictionaryType type, boolean deduplicate) {
        Set<String> mergedEntries = new LinkedHashSet<>();
        
        for (String name : names) {
            List<String> entries = getDictionary(name, type);
            if (deduplicate) {
                mergedEntries.addAll(entries);
            } else {
                mergedEntries.addAll(entries);
            }
        }
        
        List<String> finalEntries = new ArrayList<>(mergedEntries);
        savedDictionaries.put(newName, new DictionaryEntry(newName, finalEntries));
        
        return finalEntries.size();
    }
    
    public DictionaryStatistics getStatistics(String name, DictionaryType type) {
        DictionaryEntry entry = getDictionaryEntry(name, type);
        return entry != null ? entry.getStatistics() : null;
    }
    
    public List<String> searchEntries(String name, DictionaryType type, String keyword) {
        List<String> entries = getDictionary(name, type);
        if (keyword == null || keyword.isEmpty()) {
            return entries;
        }
        
        String lowerKeyword = keyword.toLowerCase();
        return entries.stream()
                .filter(e -> e.toLowerCase().contains(lowerKeyword))
                .collect(Collectors.toList());
    }
    
    public int importFromFile(String filePath, String dictionaryName, boolean deduplicate) throws IOException {
        Path path = Paths.get(filePath);
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        
        List<String> entries = lines.stream()
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
        
        if (deduplicate) {
            entries = new ArrayList<>(new LinkedHashSet<>(entries));
        }
        
        savedDictionaries.put(dictionaryName, new DictionaryEntry(dictionaryName, entries));
        
        return entries.size();
    }
    
    public void exportToFile(String name, DictionaryType type, String filePath) throws IOException {
        List<String> entries = getDictionary(name, type);
        Files.write(Paths.get(filePath), entries, StandardCharsets.UTF_8);
    }
    
    public int saveDictionaryToFile(String promptType, String chineseName, List<String> entries, boolean deduplication) {
        try {
            String fileName = configDirPath + "/" + chineseName + ".txt";
            File file = new File(fileName);
            
            Set<String> uniqueEntries = new LinkedHashSet<>();
            if (deduplication && file.exists()) {
                List<String> existingEntries = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
                uniqueEntries.addAll(existingEntries);
            }
            
            if (deduplication) {
                uniqueEntries.addAll(entries);
                entries = new ArrayList<>(uniqueEntries);
            }
            
            Files.write(file.toPath(), entries, StandardCharsets.UTF_8);
            
            savedDictionaries.put(chineseName, new DictionaryEntry(chineseName, entries));
            
            return entries.size();
        } catch (IOException e) {
            e.printStackTrace();
            return 0;
        }
    }
    
    public void loadSavedDictionaries(ConfigManager configManager) {
        File configDir = new File(configDirPath);
        if (!configDir.exists()) {
            return;
        }
        
        File[] files = configDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".txt"));
        if (files == null) {
            return;
        }
        
        for (File file : files) {
            try {
                String name = file.getName();
                if (name.toLowerCase().endsWith(".txt")) {
                    name = name.substring(0, name.length() - 4);
                }
                
                List<String> entries = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
                savedDictionaries.put(name, new DictionaryEntry(name, entries));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    public List<String> getEntriesPage(String name, DictionaryType type, int page, int pageSize) {
        List<String> entries = getDictionary(name, type);
        int start = page * pageSize;
        int end = Math.min(start + pageSize, entries.size());
        
        if (start >= entries.size()) {
            return new ArrayList<>();
        }
        
        return new ArrayList<>(entries.subList(start, end));
    }
    
    public int getPageCount(String name, DictionaryType type, int pageSize) {
        List<String> entries = getDictionary(name, type);
        return (int) Math.ceil((double) entries.size() / pageSize);
    }
}
