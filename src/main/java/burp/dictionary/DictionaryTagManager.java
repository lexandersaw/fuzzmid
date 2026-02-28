package burp.dictionary;

import java.util.*;
import java.util.stream.Collectors;

public class DictionaryTagManager {
    
    private final Map<String, Set<String>> dictionaryTags;
    private final Map<String, Set<String>> tagDictionaries;
    private final Set<String> allTags;
    
    public DictionaryTagManager() {
        this.dictionaryTags = new LinkedHashMap<>();
        this.tagDictionaries = new LinkedHashMap<>();
        this.allTags = new LinkedHashSet<>();
        
        initializeDefaultTags();
    }
    
    private void initializeDefaultTags() {
        addPredefinedTag("SQL注入", "SQL Injection");
        addPredefinedTag("XSS", "Cross-Site Scripting");
        addPredefinedTag("命令注入", "Command Injection");
        addPredefinedTag("路径遍历", "Path Traversal");
        addPredefinedTag("SSRF", "Server-Side Request Forgery");
        addPredefinedTag("XXE", "XML External Entity");
        addPredefinedTag("认证绕过", "Authentication Bypass");
        addPredefinedTag("权限提升", "Privilege Escalation");
        addPredefinedTag("WAF绕过", "WAF Bypass");
        addPredefinedTag("高价值", "High Value");
        addPredefinedTag("MySQL", "MySQL Database");
        addPredefinedTag("PostgreSQL", "PostgreSQL Database");
        addPredefinedTag("MSSQL", "Microsoft SQL Server");
        addPredefinedTag("Oracle", "Oracle Database");
        addPredefinedTag("MongoDB", "MongoDB NoSQL");
        addPredefinedTag("PHP", "PHP Application");
        addPredefinedTag("Java", "Java Application");
        addPredefinedTag("Python", "Python Application");
        addPredefinedTag("Node.js", "Node.js Application");
    }
    
    private void addPredefinedTag(String chineseName, String englishName) {
        allTags.add(chineseName);
        tagDictionaries.put(chineseName, new HashSet<>());
    }
    
    public void addTagToDictionary(String dictionaryName, String tag) {
        if (dictionaryName == null || tag == null) {
            return;
        }
        
        dictionaryTags.computeIfAbsent(dictionaryName, k -> new HashSet<>()).add(tag);
        tagDictionaries.computeIfAbsent(tag, k -> new HashSet<>()).add(dictionaryName);
        allTags.add(tag);
    }
    
    public void removeTagFromDictionary(String dictionaryName, String tag) {
        if (dictionaryName == null || tag == null) {
            return;
        }
        
        Set<String> tags = dictionaryTags.get(dictionaryName);
        if (tags != null) {
            tags.remove(tag);
        }
        
        Set<String> dicts = tagDictionaries.get(tag);
        if (dicts != null) {
            dicts.remove(dictionaryName);
        }
    }
    
    public void setDictionaryTags(String dictionaryName, Set<String> tags) {
        if (dictionaryName == null) {
            return;
        }
        
        Set<String> existingTags = dictionaryTags.get(dictionaryName);
        if (existingTags != null) {
            for (String oldTag : existingTags) {
                Set<String> dicts = tagDictionaries.get(oldTag);
                if (dicts != null) {
                    dicts.remove(dictionaryName);
                }
            }
        }
        
        if (tags != null) {
            dictionaryTags.put(dictionaryName, new HashSet<>(tags));
            for (String tag : tags) {
                tagDictionaries.computeIfAbsent(tag, k -> new HashSet<>()).add(dictionaryName);
                allTags.add(tag);
            }
        } else {
            dictionaryTags.remove(dictionaryName);
        }
    }
    
    public Set<String> getDictionaryTags(String dictionaryName) {
        Set<String> tags = dictionaryTags.get(dictionaryName);
        return tags != null ? new HashSet<>(tags) : new HashSet<>();
    }
    
    public Set<String> getDictionariesByTag(String tag) {
        Set<String> dicts = tagDictionaries.get(tag);
        return dicts != null ? new HashSet<>(dicts) : new HashSet<>();
    }
    
    public List<String> searchDictionariesByTags(Set<String> searchTags, boolean matchAll) {
        if (searchTags == null || searchTags.isEmpty()) {
            return new ArrayList<>();
        }
        
        Set<String> result = null;
        
        for (String tag : searchTags) {
            Set<String> dictsForTag = tagDictionaries.get(tag);
            if (dictsForTag == null) {
                if (matchAll) {
                    return new ArrayList<>();
                }
                continue;
            }
            
            if (result == null) {
                result = new HashSet<>(dictsForTag);
            } else if (matchAll) {
                result.retainAll(dictsForTag);
                if (result.isEmpty()) {
                    return new ArrayList<>();
                }
            } else {
                result.addAll(dictsForTag);
            }
        }
        
        return result != null ? new ArrayList<>(result) : new ArrayList<>();
    }
    
    public Set<String> getAllTags() {
        return new LinkedHashSet<>(allTags);
    }
    
    public Map<String, Integer> getTagStatistics() {
        Map<String, Integer> stats = new LinkedHashMap<>();
        for (String tag : allTags) {
            Set<String> dicts = tagDictionaries.get(tag);
            stats.put(tag, dicts != null ? dicts.size() : 0);
        }
        return stats;
    }
    
    public void removeDictionary(String dictionaryName) {
        Set<String> tags = dictionaryTags.remove(dictionaryName);
        if (tags != null) {
            for (String tag : tags) {
                Set<String> dicts = tagDictionaries.get(tag);
                if (dicts != null) {
                    dicts.remove(dictionaryName);
                }
            }
        }
    }
    
    public void renameDictionary(String oldName, String newName) {
        Set<String> tags = dictionaryTags.remove(oldName);
        if (tags != null) {
            dictionaryTags.put(newName, tags);
            
            for (String tag : tags) {
                Set<String> dicts = tagDictionaries.get(tag);
                if (dicts != null) {
                    dicts.remove(oldName);
                    dicts.add(newName);
                }
            }
        }
    }
    
    public List<String> suggestTagsForDictionary(String dictionaryName, List<String> samplePayloads) {
        Set<String> suggestedTags = new LinkedHashSet<>();
        
        if (samplePayloads != null) {
            for (String payload : samplePayloads) {
                String lower = payload.toLowerCase();
                
                if (lower.contains("select") || lower.contains("union") || 
                    lower.contains("' or ") || lower.contains("--")) {
                    suggestedTags.add("SQL注入");
                }
                
                if (lower.contains("<script") || lower.contains("javascript:") ||
                    lower.contains("onerror") || lower.contains("onload")) {
                    suggestedTags.add("XSS");
                }
                
                if (lower.contains("exec") || lower.contains("system(") ||
                    lower.contains("| cat") || lower.contains("; ls")) {
                    suggestedTags.add("命令注入");
                }
                
                if (lower.contains("../") || lower.contains("..\\") ||
                    lower.contains("%2e%2e")) {
                    suggestedTags.add("路径遍历");
                }
                
                if (lower.contains("http://127.0.0.1") || lower.contains("http://localhost") ||
                    lower.contains("file://")) {
                    suggestedTags.add("SSRF");
                }
            }
        }
        
        return new ArrayList<>(suggestedTags);
    }
    
    public void importTags(String jsonData) {
        try {
            org.json.JSONObject json = new org.json.JSONObject(jsonData);
            
            org.json.JSONArray tagsArray = json.optJSONArray("tags");
            if (tagsArray != null) {
                for (int i = 0; i < tagsArray.length(); i++) {
                    allTags.add(tagsArray.getString(i));
                }
            }
            
            org.json.JSONObject mapping = json.optJSONObject("mapping");
            if (mapping != null) {
                for (String dictName : mapping.keySet()) {
                    org.json.JSONArray dictTags = mapping.optJSONArray(dictName);
                    if (dictTags != null) {
                        Set<String> tags = new HashSet<>();
                        for (int i = 0; i < dictTags.length(); i++) {
                            tags.add(dictTags.getString(i));
                        }
                        setDictionaryTags(dictName, tags);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to import tags: " + e.getMessage());
        }
    }
    
    public String exportTags() {
        org.json.JSONObject json = new org.json.JSONObject();
        
        org.json.JSONArray tagsArray = new org.json.JSONArray();
        for (String tag : allTags) {
            tagsArray.put(tag);
        }
        json.put("tags", tagsArray);
        
        org.json.JSONObject mapping = new org.json.JSONObject();
        for (Map.Entry<String, Set<String>> entry : dictionaryTags.entrySet()) {
            org.json.JSONArray dictTags = new org.json.JSONArray();
            for (String tag : entry.getValue()) {
                dictTags.put(tag);
            }
            mapping.put(entry.getKey(), dictTags);
        }
        json.put("mapping", mapping);
        
        return json.toString(2);
    }
}
