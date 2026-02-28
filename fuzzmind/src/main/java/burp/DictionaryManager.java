package burp;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * 字典管理器类，用于管理各种字典
 */
public class DictionaryManager {
    // 存储所有生成字典的Map，键为字典名称，值为字典内容
    private final Map<String, List<String>> generatedDictionaries;
    // 存储所有保存字典的Map，键为字典名称，值为字典内容
    private final Map<String, List<String>> savedDictionaries;
    // 当前选中的字典名称
    private String selectedDictionaryName;
    // 当前选中的字典类型（生成/保存）
    private DictionaryType selectedDictionaryType;
    // 配置目录路径
    private final String CONFIG_DIR_PATH = System.getProperty("user.home") + "/.config/fuzzMind";
    
    // 字典类型枚举
    public enum DictionaryType {
        GENERATED, // 生成的字典
        SAVED      // 保存的字典
    }

    public DictionaryManager() {
        this.generatedDictionaries = new LinkedHashMap<>();
        this.savedDictionaries = new LinkedHashMap<>();
        this.selectedDictionaryName = null;
        this.selectedDictionaryType = DictionaryType.GENERATED;
        
        // 创建配置目录
        createConfigDir();
    }
    
    /**
     * 创建配置目录
     */
    private void createConfigDir() {
        File configDir = new File(CONFIG_DIR_PATH);
        if (!configDir.exists()) {
            configDir.mkdirs();
        }
    }

    /**
     * 添加新字典到生成字典
     * @param name 字典名称
     * @param entries 字典内容
     */
    public void addDictionary(String name, List<String> entries) {
        generatedDictionaries.put(name, new ArrayList<>(entries));
        
        // 如果是第一个添加的字典，则默认选中它
        if (selectedDictionaryName == null) {
            selectedDictionaryName = name;
            selectedDictionaryType = DictionaryType.GENERATED;
        }
    }

    /**
     * 更新生成字典内容
     * @param name 字典名称
     * @param entries 新的字典内容
     */
    public void updateDictionary(String name, List<String> entries) {
        if (generatedDictionaries.containsKey(name)) {
            generatedDictionaries.put(name, new ArrayList<>(entries));
        }
    }
    
    /**
     * 获取所有生成字典名称
     * @return 字典名称列表
     */
    public List<String> getGeneratedDictionaryNames() {
        return new ArrayList<>(generatedDictionaries.keySet());
    }
    
    /**
     * 获取所有保存字典名称
     * @return 字典名称列表
     */
    public List<String> getSavedDictionaryNames() {
        return new ArrayList<>(savedDictionaries.keySet());
    }

    /**
     * 获取所有字典名称
     * @return 字典名称列表
     */
    public List<String> getDictionaryNames() {
        List<String> names = new ArrayList<>();
        names.addAll(generatedDictionaries.keySet());
        names.addAll(savedDictionaries.keySet());
        return names;
    }

    /**
     * 获取指定名称的字典内容
     * @param name 字典名称
     * @param type 字典类型
     * @return 字典内容
     */
    public List<String> getDictionary(String name, DictionaryType type) {
        if (type == DictionaryType.GENERATED) {
            return generatedDictionaries.getOrDefault(name, new ArrayList<>());
        } else {
            return savedDictionaries.getOrDefault(name, new ArrayList<>());
        }
    }
    
    /**
     * 获取指定名称的字典内容（默认为生成字典）
     * @param name 字典名称
     * @return 字典内容
     */
    public List<String> getDictionary(String name) {
        return getDictionary(name, DictionaryType.GENERATED);
    }

    /**
     * 设置当前选中的字典
     * @param name 字典名称
     * @param type 字典类型
     */
    public void setSelectedDictionary(String name, DictionaryType type) {
        if ((type == DictionaryType.GENERATED && generatedDictionaries.containsKey(name)) ||
            (type == DictionaryType.SAVED && savedDictionaries.containsKey(name))) {
            selectedDictionaryName = name;
            selectedDictionaryType = type;
        }
    }
    
    /**
     * 设置当前选中的字典（默认为生成字典）
     * @param name 字典名称
     */
    public void setSelectedDictionary(String name) {
        setSelectedDictionary(name, DictionaryType.GENERATED);
    }

    /**
     * 获取当前选中的字典名称
     * @return 字典名称
     */
    public String getSelectedDictionaryName() {
        return selectedDictionaryName;
    }
    
    /**
     * 获取当前选中的字典类型
     * @return 字典类型
     */
    public DictionaryType getSelectedDictionaryType() {
        return selectedDictionaryType;
    }

    /**
     * 获取当前选中的字典内容
     * @return 字典内容
     */
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
    
    /**
     * 移除生成字典
     * @param name 字典名称
     */
    public void removeDictionary(String name) {
        generatedDictionaries.remove(name);
        
        // 如果移除的是当前选中的字典，则重新选择一个
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
    
    /**
     * 移除保存字典
     * @param name 字典名称
     */
    public void removeSavedDictionary(String name) {
        savedDictionaries.remove(name);
        
        // 删除对应的文件
        String fileName = CONFIG_DIR_PATH + "/" + name + ".txt";
        File file = new File(fileName);
        if (file.exists()) {
            file.delete();
        }
        
        // 如果移除的是当前选中的字典，则重新选择一个
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
    
    /**
     * 保存生成的字典到文件
     * @param promptType 提示词类型
     * @param chineseName 提示词类型中文名称
     * @param entries 字典内容
     * @param deduplication 是否去重
     * @return 保存后的条目数量
     */
    public int saveDictionaryToFile(String promptType, String chineseName, List<String> entries, boolean deduplication) {
        try {
            // 创建文件
            String fileName = CONFIG_DIR_PATH + "/" + chineseName + ".txt";
            File file = new File(fileName);
            
            // 如果文件已存在，且需要去重，则先读取文件内容
            Set<String> uniqueEntries = new LinkedHashSet<>();
            if (deduplication && file.exists()) {
                List<String> existingEntries = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
                uniqueEntries.addAll(existingEntries);
            }
            
            // 添加新条目
            if (deduplication) {
                uniqueEntries.addAll(entries);
                entries = new ArrayList<>(uniqueEntries);
            }
            
            // 写入文件
            Files.write(file.toPath(), entries, StandardCharsets.UTF_8);
            
            // 更新保存字典
            savedDictionaries.put(chineseName, new ArrayList<>(entries));
            
            return entries.size();
        } catch (IOException e) {
            e.printStackTrace();
            return 0;
        }
    }
    
    /**
     * 加载保存的字典
     * @param configManager 配置管理器，用于获取提示词类型的中文名称
     */
    public void loadSavedDictionaries(ConfigManager configManager) {
        File configDir = new File(CONFIG_DIR_PATH);
        if (!configDir.exists()) {
            return;
        }
        
        // 获取目录下的所有.txt文件
        File[] files = configDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".txt"));
        if (files == null) {
            return;
        }
        
        // 加载每个文件
        for (File file : files) {
            try {
                // 获取文件名（不包含扩展名）
                String name = file.getName();
                if (name.toLowerCase().endsWith(".txt")) {
                    name = name.substring(0, name.length() - 4);
                }
                
                // 读取文件内容
                List<String> entries = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
                
                // 添加到保存字典
                savedDictionaries.put(name, entries);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
} 