package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.List;
import java.util.Map;

import burp.dictionary.HistoryManager.HistoryEntry;
import burp.dictionary.EnhancedDictionaryManager.DictionaryStatistics;
import burp.payload.PayloadTransformer;
import burp.payload.PayloadTransformerFactory;
import burp.ui.HistoryPanel;
import burp.ui.SearchPanel;
import burp.ui.StatisticsPanel;
import burp.ui.TransformConfigPanel;
import burp.util.ContextAnalyzer.RequestContext;

public class FuzzMindTab extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final DictionaryManager dictionaryManager;
    private final ConfigManager configManager;
    private final AIGenerator aiGenerator;
    
    private JList<String> promptTypeList;
    private DefaultListModel<String> promptTypeListModel;
    private JTextArea promptTextArea;
    private JTextArea dictionaryTextArea;
    private JButton generateButton;
    private JButton useButton;
    private JButton configButton;
    private JButton addPromptTypeButton;
    private JButton editPromptTypeButton;
    private JButton deletePromptTypeButton;
    
    private JTabbedPane dictionaryTabbedPane;
    private JList<String> savedDictionaryList;
    private DefaultListModel<String> savedDictionaryListModel;
    private JTextArea savedDictionaryTextArea;
    private JButton saveDictionaryButton;
    private JButton deleteSavedDictionaryButton;
    private JButton useSavedDictionaryButton;
    private JButton saveSavedDictionaryButton;
    private JButton importButton;
    private JButton exportButton;
    private JButton mergeButton;
    
    private JTabbedPane mainTabbedPane;
    private TransformConfigPanel transformConfigPanel;
    private StatisticsPanel statisticsPanel;
    private SearchPanel searchPanel;
    private HistoryPanel historyPanel;
    
    private JCheckBox streamModeCheck;
    private JComboBox<String> vulnTypeCombo;
    private JTextField targetParamField;
    
    private volatile boolean isGenerating = false;
    private final Object generateLock = new Object();
    private volatile Thread currentGenerateThread;
    
    public FuzzMindTab(IBurpExtenderCallbacks callbacks, DictionaryManager dictionaryManager, ConfigManager configManager) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.dictionaryManager = dictionaryManager;
        this.configManager = configManager;
        this.aiGenerator = new AIGenerator(configManager, callbacks);
        this.aiGenerator.setHistoryManager(dictionaryManager.getHistoryManager());
        
        setLayout(new BorderLayout());
        initComponents();
        updatePromptTypeList();
        updateSavedDictionaryList();
    }
    
    private void initComponents() {
        mainTabbedPane = new JTabbedPane();
        
        JPanel mainPanel = createMainPanel();
        mainTabbedPane.addTab("主界面", mainPanel);
        
        JPanel transformPanel = createTransformPanel();
        mainTabbedPane.addTab("变换设置", transformPanel);
        
        historyPanel = new HistoryPanel(dictionaryManager.getHistoryManager());
        historyPanel.setSelectionListener(new HistoryPanel.HistorySelectionListener() {
            @Override
            public void onHistorySelected(HistoryEntry entry) {
                dictionaryTextArea.setText(String.join("\n", entry.getGeneratedPayloads()));
                JOptionPane.showMessageDialog(FuzzMindTab.this,
                        "已加载历史Payload，可以编辑后使用。",
                        "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        mainTabbedPane.addTab("历史记录", historyPanel);
        
        add(mainTabbedPane, BorderLayout.CENTER);
    }
    
    private JPanel createMainPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("提示词类型"));
        
        promptTypeListModel = new DefaultListModel<>();
        promptTypeList = new JList<>(promptTypeListModel);
        promptTypeList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        promptTypeList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    String selectedType = promptTypeList.getSelectedValue();
                    if (selectedType != null) {
                        displayPromptAndDictionary(selectedType);
                        editPromptTypeButton.setEnabled(true);
                        deletePromptTypeButton.setEnabled(true);
                        updateStatistics(selectedType);
                    } else {
                        editPromptTypeButton.setEnabled(false);
                        deletePromptTypeButton.setEnabled(false);
                    }
                }
            }
        });
        
        JScrollPane promptTypeScrollPane = new JScrollPane(promptTypeList);
        leftPanel.add(promptTypeScrollPane, BorderLayout.CENTER);
        
        JPanel promptTypeButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        addPromptTypeButton = new JButton("添加");
        addPromptTypeButton.addActionListener(e -> showAddPromptTypeDialog());
        promptTypeButtonPanel.add(addPromptTypeButton);
        
        editPromptTypeButton = new JButton("编辑");
        editPromptTypeButton.setEnabled(false);
        editPromptTypeButton.addActionListener(e -> {
            String selectedType = promptTypeList.getSelectedValue();
            if (selectedType != null) {
                showEditPromptTypeDialog(selectedType);
            }
        });
        promptTypeButtonPanel.add(editPromptTypeButton);
        
        deletePromptTypeButton = new JButton("删除");
        deletePromptTypeButton.setEnabled(false);
        deletePromptTypeButton.addActionListener(e -> {
            String selectedType = promptTypeList.getSelectedValue();
            if (selectedType != null) {
                int result = JOptionPane.showConfirmDialog(FuzzMindTab.this,
                        "确定要删除提示词类型「" + configManager.getPromptName(selectedType) + "」吗？",
                        "确认删除",
                        JOptionPane.YES_NO_OPTION);
                
                if (result == JOptionPane.YES_OPTION) {
                    configManager.removePromptType(selectedType);
                    dictionaryManager.removeDictionary(selectedType);
                    updatePromptTypeList();
                }
            }
        });
        promptTypeButtonPanel.add(deletePromptTypeButton);
        
        JPanel bottomPanel = new JPanel(new GridLayout(2, 1));
        bottomPanel.add(promptTypeButtonPanel);
        
        JPanel configPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        configButton = new JButton("API配置");
        configButton.addActionListener(e -> showConfigDialog());
        configPanel.add(configButton);
        bottomPanel.add(configPanel);
        
        leftPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        JPanel middlePanel = new JPanel(new BorderLayout());
        middlePanel.setBorder(BorderFactory.createTitledBorder("提示词"));
        
        promptTextArea = new JTextArea();
        promptTextArea.setLineWrap(true);
        promptTextArea.setWrapStyleWord(true);
        JScrollPane promptScrollPane = new JScrollPane(promptTextArea);
        middlePanel.add(promptScrollPane, BorderLayout.CENTER);
        
        JPanel middleBottomPanel = new JPanel(new BorderLayout());
        
        JPanel optionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        streamModeCheck = new JCheckBox("流式输出");
        streamModeCheck.setToolTipText("实时显示生成进度");
        optionPanel.add(streamModeCheck);
        
        middleBottomPanel.add(optionPanel, BorderLayout.WEST);
        
        generateButton = new JButton("生成字典");
        generateButton.addActionListener(e -> generateDictionary());
        
        JPanel generatePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        generatePanel.add(generateButton);
        middleBottomPanel.add(generatePanel, BorderLayout.EAST);
        
        middlePanel.add(middleBottomPanel, BorderLayout.SOUTH);
        
        dictionaryTabbedPane = new JTabbedPane();
        
        JPanel generatedDictionaryPanel = new JPanel(new BorderLayout());
        
        JPanel searchContainer = new JPanel(new BorderLayout());
        searchPanel = new SearchPanel();
        searchPanel.setSearchListener(new SearchPanel.SearchListener() {
            @Override
            public void onSearch(String keyword) {
                String selectedType = promptTypeList.getSelectedValue();
                if (selectedType != null) {
                    List<String> results = dictionaryManager.searchEntries(
                            selectedType, DictionaryManager.DictionaryType.GENERATED, keyword);
                    StringBuilder sb = new StringBuilder();
                    for (String entry : results) {
                        sb.append(entry).append("\n");
                    }
                    dictionaryTextArea.setText(sb.toString());
                    searchPanel.setResultCount(results.size(), 
                            dictionaryManager.getDictionary(selectedType).size());
                }
            }
            
            @Override
            public void onClear() {
                String selectedType = promptTypeList.getSelectedValue();
                if (selectedType != null) {
                    displayPromptAndDictionary(selectedType);
                }
            }
        });
        searchContainer.add(searchPanel, BorderLayout.NORTH);
        
        dictionaryTextArea = new JTextArea();
        dictionaryTextArea.setLineWrap(true);
        JScrollPane dictionaryContentScrollPane = new JScrollPane(dictionaryTextArea);
        searchContainer.add(dictionaryContentScrollPane, BorderLayout.CENTER);
        
        JPanel generatedActionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        saveDictionaryButton = new JButton("保存字典");
        saveDictionaryButton.addActionListener(e -> saveDictionaryToFile());
        generatedActionPanel.add(saveDictionaryButton);
        
        useButton = new JButton("使用该字典");
        useButton.addActionListener(e -> useDictionary());
        generatedActionPanel.add(useButton);
        
        searchContainer.add(generatedActionPanel, BorderLayout.SOUTH);
        generatedDictionaryPanel.add(searchContainer, BorderLayout.CENTER);
        
        JPanel savedDictionaryPanel = new JPanel(new BorderLayout());
        
        JSplitPane savedDictionarySplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        JPanel savedDictionaryListPanel = new JPanel(new BorderLayout());
        savedDictionaryListPanel.setBorder(BorderFactory.createTitledBorder("保存的字典"));
        
        savedDictionaryListModel = new DefaultListModel<>();
        savedDictionaryList = new JList<>(savedDictionaryListModel);
        savedDictionaryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        savedDictionaryList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    String selectedDictionary = savedDictionaryList.getSelectedValue();
                    if (selectedDictionary != null) {
                        displaySavedDictionary(selectedDictionary);
                        deleteSavedDictionaryButton.setEnabled(true);
                        useSavedDictionaryButton.setEnabled(true);
                        saveSavedDictionaryButton.setEnabled(true);
                    } else {
                        savedDictionaryTextArea.setText("");
                        deleteSavedDictionaryButton.setEnabled(false);
                        useSavedDictionaryButton.setEnabled(false);
                        saveSavedDictionaryButton.setEnabled(false);
                    }
                }
            }
        });
        
        JScrollPane savedDictionaryListScrollPane = new JScrollPane(savedDictionaryList);
        savedDictionaryListPanel.add(savedDictionaryListScrollPane, BorderLayout.CENTER);
        
        JPanel savedDictionaryListButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        importButton = new JButton("导入");
        importButton.addActionListener(e -> importDictionary());
        savedDictionaryListButtonPanel.add(importButton);
        
        exportButton = new JButton("导出");
        exportButton.addActionListener(e -> exportDictionary());
        savedDictionaryListButtonPanel.add(exportButton);
        
        mergeButton = new JButton("合并");
        mergeButton.addActionListener(e -> mergeDictionaries());
        savedDictionaryListButtonPanel.add(mergeButton);
        
        deleteSavedDictionaryButton = new JButton("删除");
        deleteSavedDictionaryButton.setEnabled(false);
        deleteSavedDictionaryButton.addActionListener(e -> {
            String selectedDictionary = savedDictionaryList.getSelectedValue();
            if (selectedDictionary != null) {
                int result = JOptionPane.showConfirmDialog(FuzzMindTab.this,
                        "确定要删除字典「" + selectedDictionary + "」吗？",
                        "确认删除",
                        JOptionPane.YES_NO_OPTION);
                
                if (result == JOptionPane.YES_OPTION) {
                    dictionaryManager.removeSavedDictionary(selectedDictionary);
                    updateSavedDictionaryList();
                }
            }
        });
        savedDictionaryListButtonPanel.add(deleteSavedDictionaryButton);
        
        savedDictionaryListPanel.add(savedDictionaryListButtonPanel, BorderLayout.SOUTH);
        
        JPanel savedDictionaryContentPanel = new JPanel(new BorderLayout());
        savedDictionaryContentPanel.setBorder(BorderFactory.createTitledBorder("字典内容"));
        
        savedDictionaryTextArea = new JTextArea();
        savedDictionaryTextArea.setLineWrap(true);
        JScrollPane savedDictionaryContentScrollPane = new JScrollPane(savedDictionaryTextArea);
        savedDictionaryContentPanel.add(savedDictionaryContentScrollPane, BorderLayout.CENTER);
        
        JPanel savedDictionaryActionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        saveSavedDictionaryButton = new JButton("保存更改");
        saveSavedDictionaryButton.setEnabled(false);
        saveSavedDictionaryButton.addActionListener(e -> {
            String selectedDictionary = savedDictionaryList.getSelectedValue();
            if (selectedDictionary != null) {
                String content = savedDictionaryTextArea.getText();
                String[] lines = content.split("\n");
                
                java.util.List<String> entries = new java.util.ArrayList<>();
                for (String line : lines) {
                    if (!line.trim().isEmpty()) {
                        entries.add(line.trim());
                    }
                }
                
                int count = dictionaryManager.saveDictionaryToFile(selectedDictionary, selectedDictionary, entries, false);
                
                updateSavedDictionaryList();
                
                JOptionPane.showMessageDialog(FuzzMindTab.this,
                        "字典更新成功！\n字典名称：" + selectedDictionary + "\n条目数量：" + count,
                        "保存成功",
                        JOptionPane.INFORMATION_MESSAGE);
            }
        });
        savedDictionaryActionPanel.add(saveSavedDictionaryButton);
        
        useSavedDictionaryButton = new JButton("使用该字典");
        useSavedDictionaryButton.setEnabled(false);
        useSavedDictionaryButton.addActionListener(e -> {
            String selectedDictionary = savedDictionaryList.getSelectedValue();
            if (selectedDictionary != null) {
                dictionaryManager.setSelectedDictionary(selectedDictionary, DictionaryManager.DictionaryType.SAVED);
                
                JOptionPane.showMessageDialog(FuzzMindTab.this,
                        "已选择「" + selectedDictionary + "」作为Intruder有效载荷\n" +
                        "现在您可以在Intruder中选择「FuzzMind Payload Generator」使用该字典",
                        "FuzzMind", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        savedDictionaryActionPanel.add(useSavedDictionaryButton);
        savedDictionaryContentPanel.add(savedDictionaryActionPanel, BorderLayout.SOUTH);
        
        savedDictionarySplitPane.setLeftComponent(savedDictionaryListPanel);
        savedDictionarySplitPane.setRightComponent(savedDictionaryContentPanel);
        savedDictionarySplitPane.setDividerLocation(200);
        
        savedDictionaryPanel.add(savedDictionarySplitPane, BorderLayout.CENTER);
        
        dictionaryTabbedPane.addTab("生成字典", generatedDictionaryPanel);
        dictionaryTabbedPane.addTab("存储字典", savedDictionaryPanel);
        
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, middlePanel, dictionaryTabbedPane);
        rightSplitPane.setDividerLocation(400);
        
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightSplitPane);
        mainSplitPane.setDividerLocation(200);
        
        panel.add(mainSplitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createTransformPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        transformConfigPanel = new TransformConfigPanel();
        panel.add(transformConfigPanel, BorderLayout.NORTH);
        
        statisticsPanel = new StatisticsPanel();
        panel.add(statisticsPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void showAddPromptTypeDialog() {
        JPanel panel = new JPanel(new GridLayout(0, 1));
        
        JPanel keyPanel = new JPanel(new BorderLayout());
        keyPanel.add(new JLabel("提示词类型标识（英文）: "), BorderLayout.WEST);
        JTextField keyField = new JTextField(20);
        keyPanel.add(keyField, BorderLayout.CENTER);
        panel.add(keyPanel);
        
        JPanel namePanel = new JPanel(new BorderLayout());
        namePanel.add(new JLabel("提示词类型名称（中文）: "), BorderLayout.WEST);
        JTextField nameField = new JTextField(20);
        namePanel.add(nameField, BorderLayout.CENTER);
        panel.add(namePanel);
        
        JPanel promptPanel = new JPanel(new BorderLayout());
        promptPanel.add(new JLabel("提示词模板: "), BorderLayout.NORTH);
        JTextArea promptArea = new JTextArea(10, 30);
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(promptArea);
        promptPanel.add(scrollPane, BorderLayout.CENTER);
        panel.add(promptPanel);
        
        int result = JOptionPane.showConfirmDialog(this, panel, "添加提示词类型", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            String key = keyField.getText().trim();
            String name = nameField.getText().trim();
            String prompt = promptArea.getText().trim();
            
            if (key.isEmpty() || name.isEmpty() || prompt.isEmpty()) {
                JOptionPane.showMessageDialog(this, "所有字段都不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            if (configManager.getPromptTypes().contains(key)) {
                JOptionPane.showMessageDialog(this, "提示词类型「" + key + "」已存在", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            configManager.addPromptType(key, name, prompt);
            dictionaryManager.addDictionary(key, new java.util.ArrayList<>());
            updatePromptTypeList();
            promptTypeList.setSelectedValue(key, true);
            
            JOptionPane.showMessageDialog(this, "提示词类型添加成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void showEditPromptTypeDialog(String promptType) {
        JPanel panel = new JPanel(new GridLayout(0, 1));
        
        JPanel keyPanel = new JPanel(new BorderLayout());
        keyPanel.add(new JLabel("提示词类型标识（英文）: "), BorderLayout.WEST);
        JTextField keyField = new JTextField(promptType, 20);
        keyField.setEditable(false);
        keyPanel.add(keyField, BorderLayout.CENTER);
        panel.add(keyPanel);
        
        JPanel namePanel = new JPanel(new BorderLayout());
        namePanel.add(new JLabel("提示词类型名称（中文）: "), BorderLayout.WEST);
        JTextField nameField = new JTextField(configManager.getPromptName(promptType), 20);
        namePanel.add(nameField, BorderLayout.CENTER);
        panel.add(namePanel);
        
        JPanel promptPanel = new JPanel(new BorderLayout());
        promptPanel.add(new JLabel("提示词模板: "), BorderLayout.NORTH);
        JTextArea promptArea = new JTextArea(configManager.getPromptTemplate(promptType), 10, 30);
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(promptArea);
        promptPanel.add(scrollPane, BorderLayout.CENTER);
        panel.add(promptPanel);
        
        int result = JOptionPane.showConfirmDialog(this, panel, "编辑提示词类型", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String prompt = promptArea.getText().trim();
            
            if (name.isEmpty() || prompt.isEmpty()) {
                JOptionPane.showMessageDialog(this, "所有字段都不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            configManager.updatePromptType(promptType, name, prompt);
            displayPromptAndDictionary(promptType);
            
            JOptionPane.showMessageDialog(this, "提示词类型更新成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void showConfigDialog() {
        JPanel panel = new JPanel(new GridLayout(0, 1));
        
        JPanel baseUrlPanel = new JPanel(new BorderLayout());
        baseUrlPanel.add(new JLabel("API Base URL: "), BorderLayout.WEST);
        JTextField baseUrlField = new JTextField(configManager.getConfig(ConfigManager.BASE_URL, "https://api.openai.com/v1/chat/completions"), 40);
        baseUrlPanel.add(baseUrlField, BorderLayout.CENTER);
        panel.add(baseUrlPanel);
        
        JPanel apiKeyPanel = new JPanel(new BorderLayout());
        apiKeyPanel.add(new JLabel("API Key: "), BorderLayout.WEST);
        JTextField apiKeyField = new JTextField(configManager.getConfig(ConfigManager.API_KEY), 40);
        apiKeyPanel.add(apiKeyField, BorderLayout.CENTER);
        panel.add(apiKeyPanel);
        
        JPanel modelPanel = new JPanel(new BorderLayout());
        modelPanel.add(new JLabel("Model: "), BorderLayout.WEST);
        JTextField modelField = new JTextField(configManager.getConfig(ConfigManager.MODEL, "gpt-3.5-turbo"), 40);
        modelPanel.add(modelField, BorderLayout.CENTER);
        panel.add(modelPanel);
        
        JPanel timeoutPanel = new JPanel(new BorderLayout());
        timeoutPanel.add(new JLabel("超时时间(秒): "), BorderLayout.WEST);
        JTextField timeoutField = new JTextField(configManager.getConfig("timeout", "60"), 10);
        timeoutPanel.add(timeoutField, BorderLayout.CENTER);
        panel.add(timeoutPanel);
        
        JPanel tipPanel = new JPanel(new BorderLayout());
        tipPanel.add(new JLabel("<html><i>常用配置示例：<br>" +
                "OpenAI: https://api.openai.com/v1/chat/completions, gpt-3.5-turbo<br>" +
                "DeepSeek: https://api.deepseek.com/v1/chat/completions, deepseek-chat<br>" +
                "自定义服务: 填入对应的 API 地址和模型名称</i></html>"), BorderLayout.WEST);
        panel.add(tipPanel);
        
        int result = JOptionPane.showConfirmDialog(this, panel, "API配置", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            configManager.setConfig(ConfigManager.BASE_URL, baseUrlField.getText().trim());
            configManager.setConfig(ConfigManager.API_KEY, apiKeyField.getText().trim());
            configManager.setConfig(ConfigManager.MODEL, modelField.getText().trim());
            configManager.setConfig("timeout", timeoutField.getText().trim());
            JOptionPane.showMessageDialog(this, "API配置已保存", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void updatePromptTypeList() {
        String selectedType = promptTypeList.getSelectedValue();
        
        promptTypeListModel.clear();
        for (String type : configManager.getPromptTypes()) {
            promptTypeListModel.addElement(type);
        }
        
        if (selectedType != null && promptTypeListModel.contains(selectedType)) {
            promptTypeList.setSelectedValue(selectedType, true);
        } else if (!promptTypeListModel.isEmpty()) {
            promptTypeList.setSelectedIndex(0);
        }
    }
    
    private void displayPromptAndDictionary(String promptType) {
        promptTextArea.setText(configManager.getPromptTemplate(promptType));
        
        List<String> entries = dictionaryManager.getDictionary(promptType);
        StringBuilder sb = new StringBuilder();
        for (String entry : entries) {
            sb.append(entry).append("\n");
        }
        dictionaryTextArea.setText(sb.toString());
    }
    
    private void updateStatistics(String promptType) {
        DictionaryStatistics stats = dictionaryManager.getStatistics(promptType, DictionaryManager.DictionaryType.GENERATED);
        statisticsPanel.updateStatistics(stats);
    }
    
    private void generateDictionary() {
        synchronized (generateLock) {
            if (isGenerating) {
                int result = JOptionPane.showConfirmDialog(this,
                        "当前正在生成中，是否取消当前生成任务？",
                        "确认",
                        JOptionPane.YES_NO_OPTION);
                if (result == JOptionPane.YES_OPTION) {
                    cancelGeneration();
                }
                return;
            }
        }
        
        String selectedType = promptTypeList.getSelectedValue();
        String prompt = promptTextArea.getText();
        
        if (selectedType == null) {
            JOptionPane.showMessageDialog(this, "请先选择一个提示词类型", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        configManager.updatePromptTemplate(selectedType, prompt);
        
        String apiKey = configManager.getConfig(ConfigManager.API_KEY);
        if (apiKey == null || apiKey.trim().isEmpty()) {
            int result = JOptionPane.showConfirmDialog(this,
                    "API配置不完整，是否现在配置？",
                    "API配置",
                    JOptionPane.YES_NO_OPTION);
            
            if (result == JOptionPane.YES_OPTION) {
                showConfigDialog();
                apiKey = configManager.getConfig(ConfigManager.API_KEY);
                if (apiKey == null || apiKey.trim().isEmpty()) {
                    return;
                }
            } else {
                return;
            }
        }
        
        synchronized (generateLock) {
            isGenerating = true;
        }
        generateButton.setEnabled(false);
        generateButton.setText("生成中...");
        dictionaryTextArea.setText("");
        
        if (streamModeCheck.isSelected()) {
            generateDictionaryStream(selectedType, prompt);
        } else {
            generateDictionaryNormal(selectedType, prompt);
        }
    }
    
    private void cancelGeneration() {
        Thread threadToCancel;
        synchronized (generateLock) {
            threadToCancel = currentGenerateThread;
            currentGenerateThread = null;
            isGenerating = false;
        }
        
        if (threadToCancel != null && threadToCancel.isAlive()) {
            threadToCancel.interrupt();
        }
        
        SwingUtilities.invokeLater(() -> {
            generateButton.setText("生成字典");
            generateButton.setEnabled(true);
        });
    }
    
    private void generateDictionaryNormal(String selectedType, String prompt) {
        Thread newThread = new Thread(() -> {
            final StringBuilder localBuffer = new StringBuilder();
            try {
                final List<String> generatedPayloads = aiGenerator.generateDictionary(selectedType, prompt);
                
                if (Thread.currentThread().isInterrupted()) {
                    return;
                }
                
                SwingUtilities.invokeLater(() -> {
                    StringBuilder sb = new StringBuilder();
                    for (String payload : generatedPayloads) {
                        sb.append(payload).append("\n");
                    }
                    dictionaryTextArea.setText(sb.toString());
                    
                    dictionaryManager.updateDictionary(selectedType, generatedPayloads);
                    updateStatistics(selectedType);
                    
                    synchronized (generateLock) {
                        isGenerating = false;
                    }
                    generateButton.setText("生成字典");
                    generateButton.setEnabled(true);
                    
                    historyPanel.refresh();
                    
                    JOptionPane.showMessageDialog(FuzzMindTab.this,
                            "字典生成完成！\n生成了 " + generatedPayloads.size() + " 个条目\n" +
                            "您可以直接编辑内容，然后点击「使用该字典」按钮。",
                            "FuzzMind", JOptionPane.INFORMATION_MESSAGE);
                });
            } catch (final Exception e) {
                if (Thread.currentThread().isInterrupted()) {
                    return;
                }
                SwingUtilities.invokeLater(() -> {
                    synchronized (generateLock) {
                        isGenerating = false;
                    }
                    generateButton.setText("生成字典");
                    generateButton.setEnabled(true);
                    JOptionPane.showMessageDialog(FuzzMindTab.this,
                            "生成失败：" + e.getMessage(),
                            "错误", JOptionPane.ERROR_MESSAGE);
                });
            }
        });
        synchronized (generateLock) {
            currentGenerateThread = newThread;
        }
        newThread.start();
    }
    
    private void generateDictionaryStream(String selectedType, String prompt) {
        final StringBuilder localBuffer = new StringBuilder();
        
        Thread newThread = new Thread(() -> {
            aiGenerator.generateDictionaryStream(selectedType, prompt,
                chunk -> {
                    if (Thread.currentThread().isInterrupted()) {
                        return;
                    }
                    SwingUtilities.invokeLater(() -> {
                        localBuffer.append(chunk);
                        String displayText = localBuffer.toString();
                        StringBuilder formatted = new StringBuilder();
                        for (String line : displayText.strip().split("\n")) {
                            line = line.strip();
                            if (!line.isEmpty() && !line.startsWith("#") && !line.startsWith("```")) {
                                if (line.matches("^\\d+\\.\\s.*")) {
                                    line = line.replaceFirst("^\\d+\\.\\s+", "");
                                }
                                formatted.append(line).append("\n");
                            }
                        }
                        dictionaryTextArea.setText(formatted.toString());
                    });
                },
                () -> {
                    if (Thread.currentThread().isInterrupted()) {
                        return;
                    }
                    SwingUtilities.invokeLater(() -> {
                        String text = localBuffer.toString();
                        List<String> payloads = processGeneratedText(text);
                        
                        dictionaryManager.updateDictionary(selectedType, payloads);
                        updateStatistics(selectedType);
                        
                        synchronized (generateLock) {
                            isGenerating = false;
                        }
                        generateButton.setText("生成字典");
                        generateButton.setEnabled(true);
                        
                        historyPanel.refresh();
                        
                        JOptionPane.showMessageDialog(FuzzMindTab.this,
                                "字典生成完成！\n生成了 " + payloads.size() + " 个条目",
                                "FuzzMind", JOptionPane.INFORMATION_MESSAGE);
                    });
                },
                error -> {
                    if (Thread.currentThread().isInterrupted()) {
                        return;
                    }
                    SwingUtilities.invokeLater(() -> {
                        synchronized (generateLock) {
                            isGenerating = false;
                        }
                        generateButton.setText("生成字典");
                        generateButton.setEnabled(true);
                        JOptionPane.showMessageDialog(FuzzMindTab.this,
                                "生成失败：" + error.getMessage(),
                                "错误", JOptionPane.ERROR_MESSAGE);
                    });
                }
            );
        });
        synchronized (generateLock) {
            currentGenerateThread = newThread;
        }
        newThread.start();
    }
    
    private List<String> processGeneratedText(String text) {
        List<String> payloads = new java.util.ArrayList<>();
        for (String line : text.strip().split("\n")) {
            line = line.strip();
            if (!line.isEmpty() && !line.startsWith("#") && !line.startsWith("```")) {
                if (line.matches("^\\d+\\.\\s.*")) {
                    line = line.replaceFirst("^\\d+\\.\\s+", "");
                }
                payloads.add(line);
            }
        }
        return payloads;
    }
    
    private void useDictionary() {
        String selectedType = promptTypeList.getSelectedValue();
        if (selectedType == null) {
            JOptionPane.showMessageDialog(this, "请先选择一个提示词类型", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        String content = dictionaryTextArea.getText();
        String[] lines = content.split("\\n");
        
        java.util.List<String> entries = new java.util.ArrayList<>();
        for (String line : lines) {
            if (!line.trim().isEmpty()) {
                entries.add(line.trim());
            }
        }
        
        List<PayloadTransformer> transformers = transformConfigPanel.getTransformers();
        
        if (transformConfigPanel.isGenerateVariants()) {
            entries = burp.payload.PayloadTransformerFactory.generateAllVariants(entries);
        } else if (!transformers.isEmpty()) {
            entries = burp.payload.PayloadTransformerFactory.transformWithMultiple(entries, transformers);
        }
        
        dictionaryManager.updateDictionary(selectedType, entries);
        dictionaryManager.setSelectedDictionary(selectedType);
        
        JOptionPane.showMessageDialog(FuzzMindTab.this,
                "已选择「" + configManager.getPromptName(selectedType) + "」作为Intruder有效载荷\n" +
                "实际payload数量: " + entries.size() + "\n" +
                "现在您可以在Intruder中选择「FuzzMind Payload Generator」使用该字典",
                "FuzzMind", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void updateSavedDictionaryList() {
        String selectedDictionary = savedDictionaryList.getSelectedValue();
        
        savedDictionaryListModel.clear();
        for (String name : dictionaryManager.getSavedDictionaryNames()) {
            savedDictionaryListModel.addElement(name);
        }
        
        if (selectedDictionary != null && savedDictionaryListModel.contains(selectedDictionary)) {
            savedDictionaryList.setSelectedValue(selectedDictionary, true);
        } else if (!savedDictionaryListModel.isEmpty()) {
            savedDictionaryList.setSelectedIndex(0);
        }
    }
    
    private void displaySavedDictionary(String dictionaryName) {
        List<String> entries = dictionaryManager.getDictionary(dictionaryName, DictionaryManager.DictionaryType.SAVED);
        StringBuilder sb = new StringBuilder();
        for (String entry : entries) {
            sb.append(entry).append("\n");
        }
        savedDictionaryTextArea.setText(sb.toString());
    }
    
    private void saveDictionaryToFile() {
        String selectedType = promptTypeList.getSelectedValue();
        if (selectedType == null) {
            JOptionPane.showMessageDialog(this, "请先选择一个提示词类型", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        String content = dictionaryTextArea.getText();
        String[] lines = content.split("\\n");
        
        java.util.List<String> entries = new java.util.ArrayList<>();
        for (String line : lines) {
            if (!line.trim().isEmpty()) {
                entries.add(line.trim());
            }
        }
        
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "字典内容为空，无法保存", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        int result = JOptionPane.showConfirmDialog(this,
                "是否对字典内容进行去重？\n" +
                "如果选择「是」，将会与已有的字典内容合并并去重。\n" +
                "如果选择「否」，将直接覆盖原有字典内容。",
                "保存字典",
                JOptionPane.YES_NO_CANCEL_OPTION);
        
        if (result == JOptionPane.CANCEL_OPTION) {
            return;
        }
        
        boolean deduplication = (result == JOptionPane.YES_OPTION);
        
        String chineseName = configManager.getPromptName(selectedType);
        int count = dictionaryManager.saveDictionaryToFile(selectedType, chineseName, entries, deduplication);
        
        updateSavedDictionaryList();
        
        JOptionPane.showMessageDialog(this,
                "字典保存成功！\n" +
                "字典名称：" + chineseName + "\n" +
                "条目数量：" + count + "\n" +
                "保存位置：~/.config/fuzzMind/" + chineseName + ".txt",
                "保存成功",
                JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void importDictionary() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择要导入的字典文件");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            String name = file.getName();
            if (name.contains(".")) {
                name = name.substring(0, name.lastIndexOf('.'));
            }
            
            String dictionaryName = JOptionPane.showInputDialog(this, "请输入字典名称:", name);
            if (dictionaryName != null && !dictionaryName.trim().isEmpty()) {
                try {
                    int count = dictionaryManager.importFromFile(file.getAbsolutePath(), dictionaryName);
                    updateSavedDictionaryList();
                    JOptionPane.showMessageDialog(this,
                            "导入成功！\n字典名称：" + dictionaryName + "\n条目数量：" + count,
                            "导入成功", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(this,
                            "导入失败：" + e.getMessage(),
                            "错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }
    
    private void exportDictionary() {
        String selectedDictionary = savedDictionaryList.getSelectedValue();
        if (selectedDictionary == null) {
            JOptionPane.showMessageDialog(this, "请先选择一个字典", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("保存字典文件");
        fileChooser.setSelectedFile(new File(selectedDictionary + ".txt"));
        
        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                dictionaryManager.exportToFile(selectedDictionary, DictionaryManager.DictionaryType.SAVED, file.getAbsolutePath());
                JOptionPane.showMessageDialog(this,
                        "导出成功！\n文件路径：" + file.getAbsolutePath(),
                        "导出成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                        "导出失败：" + e.getMessage(),
                        "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private void mergeDictionaries() {
        java.util.List<String> names = dictionaryManager.getSavedDictionaryNames();
        if (names.size() < 2) {
            JOptionPane.showMessageDialog(this, "至少需要2个字典才能合并", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        JList<String> list = new JList<>(names.toArray(new String[0]));
        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        
        JScrollPane scrollPane = new JScrollPane(list);
        scrollPane.setPreferredSize(new Dimension(200, 150));
        
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.add(new JLabel("选择要合并的字典（按住Ctrl多选）:"), BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        JTextField nameField = new JTextField("merged_dictionary");
        JPanel namePanel = new JPanel(new BorderLayout());
        namePanel.add(new JLabel("新字典名称: "), BorderLayout.WEST);
        namePanel.add(nameField, BorderLayout.CENTER);
        panel.add(namePanel, BorderLayout.SOUTH);
        
        int result = JOptionPane.showConfirmDialog(this, panel, "合并字典", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            java.util.List<String> selected = list.getSelectedValuesList();
            if (selected.size() < 2) {
                JOptionPane.showMessageDialog(this, "请至少选择2个字典", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            String newName = nameField.getText().trim();
            if (newName.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请输入新字典名称", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            int count = dictionaryManager.mergeDictionaries(selected, newName, true);
            updateSavedDictionaryList();
            
            JOptionPane.showMessageDialog(this,
                    "合并成功！\n新字典：" + newName + "\n条目数量：" + count,
                    "合并成功", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    // 方法供 BurpExtender 调用
    public void setSelectedIndex(int index) {
        if (dictionaryTabbedPane != null && index >= 0 && index < dictionaryTabbedPane.getTabCount()) {
            dictionaryTabbedPane.setSelectedIndex(index);
        }
    }
    
    public void setGeneratingState(boolean generating) {
        if (generateButton != null) {
            generateButton.setEnabled(!generating);
            generateButton.setText(generating ? "生成中..." : "生成字典");
        }
    }
    
    public void updateDictionaryDisplay(String dictName, List<String> payloads) {
        if (dictionaryTextArea != null && payloads != null) {
            StringBuilder sb = new StringBuilder();
            for (String payload : payloads) {
                sb.append(payload).append("\n");
            }
            dictionaryTextArea.setText(sb.toString());
        }
    }
}
