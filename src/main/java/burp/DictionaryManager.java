package burp;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

import burp.dictionary.EnhancedDictionaryManager;
import burp.dictionary.EnhancedDictionaryManager.DictionaryEntry;
import burp.dictionary.EnhancedDictionaryManager.DictionaryStatistics;
import burp.dictionary.EnhancedDictionaryManager.DictionaryType;
import burp.dictionary.HistoryManager;
import burp.payload.PayloadTransformer;

public class DictionaryManager {
    private final EnhancedDictionaryManager enhancedManager;
    private final HistoryManager historyManager;
    
    private final Map<String, List<String>> generatedDictionaries;
    private final Map<String, List<String>> savedDictionaries;
    private String selectedDictionaryName;
    private DictionaryType selectedDictionaryType;
    private final String CONFIG_DIR_PATH = System.getProperty("user.home") + "/.config/fuzzMind";
    
    public enum DictionaryType {
        GENERATED,
        SAVED
    }
    
    public DictionaryManager() {
        this.enhancedManager = new EnhancedDictionaryManager();
        this.historyManager = new HistoryManager();
        this.generatedDictionaries = new LinkedHashMap<>();
        this.savedDictionaries = new LinkedHashMap<>();
        this.selectedDictionaryName = null;
        this.selectedDictionaryType = DictionaryType.GENERATED;
        
        createConfigDir();
    }
    
    private void createConfigDir() {
        File configDir = new File(CONFIG_DIR_PATH);
        if (!configDir.exists()) {
            configDir.mkdirs();
        }
    }
    
    public HistoryManager getHistoryManager() {
        return historyManager;
    }
    
    public EnhancedDictionaryManager getEnhancedManager() {
        return enhancedManager;
    }
    
    public void addDictionary(String name, List<String> entries) {
        generatedDictionaries.put(name, new ArrayList<>(entries));
        enhancedManager.addDictionary(name, entries);
        
        if (selectedDictionaryName == null) {
            selectedDictionaryName = name;
            selectedDictionaryType = DictionaryType.GENERATED;
        }
    }
    
    public void updateDictionary(String name, List<String> entries) {
        if (generatedDictionaries.containsKey(name)) {
            generatedDictionaries.put(name, new ArrayList<>(entries));
            enhancedManager.updateDictionary(name, entries);
        }
    }
    
    public List<String> getGeneratedDictionaryNames() {
        return new ArrayList<>(generatedDictionaries.keySet());
    }
    
    public List<String> getSavedDictionaryNames() {
        return new ArrayList<>(savedDictionaries.keySet());
    }
    
    public List<String> getDictionaryNames() {
        List<String> names = new ArrayList<>();
        names.addAll(generatedDictionaries.keySet());
        names.addAll(savedDictionaries.keySet());
        return names;
    }
    
    public List<String> getDictionary(String name, DictionaryType type) {
        if (type == DictionaryType.GENERATED) {
            return generatedDictionaries.getOrDefault(name, new ArrayList<>());
        } else {
            return savedDictionaries.getOrDefault(name, new ArrayList<>());
        }
    }
    
    public List<String> getDictionary(String name) {
        return getDictionary(name, DictionaryType.GENERATED);
    }
    
    public void setSelectedDictionary(String name, DictionaryType type) {
        if ((type == DictionaryType.GENERATED && generatedDictionaries.containsKey(name)) ||
            (type == DictionaryType.SAVED && savedDictionaries.containsKey(name))) {
            selectedDictionaryName = name;
            selectedDictionaryType = type;
            enhancedManager.setSelectedDictionary(name, 
                type == DictionaryType.GENERATED ? 
                EnhancedDictionaryManager.DictionaryType.GENERATED : 
                EnhancedDictionaryManager.DictionaryType.SAVED);
        }
    }
    
    public void setSelectedDictionary(String name) {
        setSelectedDictionary(name, DictionaryType.GENERATED);
    }
    
    public String getSelectedDictionaryName() {
        return selectedDictionaryName;
    }
    
    public DictionaryType getSelectedDictionaryType() {
        return selectedDictionaryType;
    }
    
    public List<String> getSelectedDictionary() {
        if (selectedDictionaryName == null) {
            return new ArrayList<>();
        }
        
        if (selectedDictionaryType == DictionaryType.GENERATED) {
            return generatedDictionaries.get(selectedDictionaryName);
        } else {
            return savedDictionaries.get(selectedDictionaryName);
        }
    }
    
    public void removeDictionary(String name) {
        generatedDictionaries.remove(name);
        enhancedManager.removeDictionary(name);
        
        if (name.equals(selectedDictionaryName) && selectedDictionaryType == DictionaryType.GENERATED) {
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
    
    public void removeSavedDictionary(String name) {
        savedDictionaries.remove(name);
        enhancedManager.removeSavedDictionary(name);
        
        if (name.equals(selectedDictionaryName) && selectedDictionaryType == DictionaryType.SAVED) {
            if (!savedDictionaries.isEmpty()) {
                selectedDictionaryName = savedDictionaries.keySet().iterator().next();
                selectedDictionaryType = DictionaryType.SAVED;
            } else if (!generatedDictionaries.isEmpty()) {
                selectedDictionaryName = generatedDictionaries.keySet().iterator().next();
                selectedDictionaryType = DictionaryType.GENERATED;
            } else {
                selectedDictionaryName = null;
            }
        }
    }
    
    public int saveDictionaryToFile(String promptType, String chineseName, List<String> entries, boolean deduplication) {
        try {
            String fileName = CONFIG_DIR_PATH + "/" + chineseName + ".txt";
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
            
            savedDictionaries.put(chineseName, new ArrayList<>(entries));
            enhancedManager.saveDictionaryToFile(promptType, chineseName, entries, deduplication);
            
            return entries.size();
        } catch (IOException e) {
            e.printStackTrace();
            return 0;
        }
    }
    
    public void loadSavedDictionaries(ConfigManager configManager) {
        File configDir = new File(CONFIG_DIR_PATH);
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
                savedDictionaries.put(name, entries);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        
        enhancedManager.loadSavedDictionaries(configManager);
    }
    
    public DictionaryStatistics getStatistics(String name, DictionaryType type) {
        return enhancedManager.getStatistics(name, 
            type == DictionaryType.GENERATED ? 
            EnhancedDictionaryManager.DictionaryType.GENERATED : 
            EnhancedDictionaryManager.DictionaryType.SAVED);
    }
    
    public List<String> searchEntries(String name, DictionaryType type, String keyword) {
        return enhancedManager.searchEntries(name, 
            type == DictionaryType.GENERATED ? 
            EnhancedDictionaryManager.DictionaryType.GENERATED : 
            EnhancedDictionaryManager.DictionaryType.SAVED, 
            keyword);
    }
    
    public int mergeDictionaries(List<String> names, String newName, boolean deduplicate) {
        Set<String> mergedEntries = new LinkedHashSet<>();
        
        for (String name : names) {
            List<String> entries = getDictionary(name, DictionaryType.SAVED);
            mergedEntries.addAll(entries);
        }
        
        List<String> finalEntries = new ArrayList<>(mergedEntries);
        savedDictionaries.put(newName, finalEntries);
        
        return finalEntries.size();
    }
    
    public int importFromFile(String filePath, String dictionaryName) throws IOException {
        List<String> lines = Files.readAllLines(new File(filePath).toPath(), StandardCharsets.UTF_8);
        List<String> entries = new ArrayList<>();
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty()) {
                entries.add(line);
            }
        }
        savedDictionaries.put(dictionaryName, entries);
        return entries.size();
    }
    
    public void exportToFile(String name, DictionaryType type, String filePath) throws IOException {
        List<String> entries = getDictionary(name, type);
        Files.write(new File(filePath).toPath(), entries, StandardCharsets.UTF_8);
    }
    
    public List<String> getEntriesPage(String name, DictionaryType type, int page, int pageSize) {
        return enhancedManager.getEntriesPage(name, 
            type == DictionaryType.GENERATED ? 
            EnhancedDictionaryManager.DictionaryType.GENERATED : 
            EnhancedDictionaryManager.DictionaryType.SAVED, 
            page, pageSize);
    }
    
    public int getPageCount(String name, DictionaryType type, int pageSize) {
        return enhancedManager.getPageCount(name, 
            type == DictionaryType.GENERATED ? 
            EnhancedDictionaryManager.DictionaryType.GENERATED : 
            EnhancedDictionaryManager.DictionaryType.SAVED, 
            pageSize);
    }
}
