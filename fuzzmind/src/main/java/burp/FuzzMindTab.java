package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * FuzzMind插件的主UI标签页
 */
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
    
    // 字典管理相关
    private JTabbedPane dictionaryTabbedPane;
    private JList<String> savedDictionaryList;
    private DefaultListModel<String> savedDictionaryListModel;
    private JTextArea savedDictionaryTextArea;
    private JButton saveDictionaryButton;
    private JButton deleteSavedDictionaryButton;
    private JButton useSavedDictionaryButton;
    private JButton saveSavedDictionaryButton;
    
    /**
     * 构造函数
     * @param callbacks Burp回调对象
     * @param dictionaryManager 字典管理器
     * @param configManager 配置管理器
     */
    public FuzzMindTab(IBurpExtenderCallbacks callbacks, DictionaryManager dictionaryManager, ConfigManager configManager) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.dictionaryManager = dictionaryManager;
        this.configManager = configManager;
        this.aiGenerator = new AIGenerator(configManager, callbacks);
        
        // 设置布局
        setLayout(new BorderLayout());
        
        // 创建UI组件
        initComponents();
        
        // 更新提示词类型列表
        updatePromptTypeList();
        
        // 更新保存的字典列表
        updateSavedDictionaryList();
    }
    
    /**
     * 初始化UI组件
     */
    private void initComponents() {
        // 创建左侧提示词类型列表面板
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
                    } else {
                        editPromptTypeButton.setEnabled(false);
                        deletePromptTypeButton.setEnabled(false);
                    }
                }
            }
        });
        
        JScrollPane promptTypeScrollPane = new JScrollPane(promptTypeList);
        leftPanel.add(promptTypeScrollPane, BorderLayout.CENTER);
        
        // 添加提示词类型管理按钮面板
        JPanel promptTypeButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        addPromptTypeButton = new JButton("添加");
        addPromptTypeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showAddPromptTypeDialog();
            }
        });
        promptTypeButtonPanel.add(addPromptTypeButton);
        
        editPromptTypeButton = new JButton("编辑");
        editPromptTypeButton.setEnabled(false);
        editPromptTypeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedType = promptTypeList.getSelectedValue();
                if (selectedType != null) {
                    showEditPromptTypeDialog(selectedType);
                }
            }
        });
        promptTypeButtonPanel.add(editPromptTypeButton);
        
        deletePromptTypeButton = new JButton("删除");
        deletePromptTypeButton.setEnabled(false);
        deletePromptTypeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedType = promptTypeList.getSelectedValue();
                if (selectedType != null) {
                    int result = JOptionPane.showConfirmDialog(FuzzMindTab.this, 
                            "确定要删除提示词类型「" + configManager.getPromptName(selectedType) + "」吗？", 
                            "确认删除", 
                            JOptionPane.YES_NO_OPTION);
                    
                    if (result == JOptionPane.YES_OPTION) {
                        // 从配置中删除提示词类型
                        configManager.removePromptType(selectedType);
                        
                        // 从字典管理器中删除对应字典
                        dictionaryManager.removeDictionary(selectedType);
                        
                        // 更新列表
                        updatePromptTypeList();
                    }
                }
            }
        });
        promptTypeButtonPanel.add(deletePromptTypeButton);
        
        // 添加配置按钮
        configButton = new JButton("配置API密钥");
        configButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showConfigDialog();
            }
        });
        
        JPanel bottomPanel = new JPanel(new GridLayout(2, 1));
        bottomPanel.add(promptTypeButtonPanel);
        
        JPanel configPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        configPanel.add(configButton);
        bottomPanel.add(configPanel);
        
        leftPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        // 创建中间提示词面板
        JPanel middlePanel = new JPanel(new BorderLayout());
        middlePanel.setBorder(BorderFactory.createTitledBorder("提示词"));
        
        // 提示词文本区域
        promptTextArea = new JTextArea();
        promptTextArea.setLineWrap(true);
        promptTextArea.setWrapStyleWord(true);
        JScrollPane promptScrollPane = new JScrollPane(promptTextArea);
        middlePanel.add(promptScrollPane, BorderLayout.CENTER);
        
        // 生成按钮
        generateButton = new JButton("生成字典");
        generateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                generateDictionary();
            }
        });
        
        JPanel generatePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        generatePanel.add(generateButton);
        middlePanel.add(generatePanel, BorderLayout.SOUTH);
        
        // 创建右侧字典内容标签页面板
        dictionaryTabbedPane = new JTabbedPane();
        
        // 创建生成字典面板
        JPanel generatedDictionaryPanel = new JPanel(new BorderLayout());
        
        // 字典内容文本区域
        dictionaryTextArea = new JTextArea();
        dictionaryTextArea.setLineWrap(true);
        JScrollPane dictionaryContentScrollPane = new JScrollPane(dictionaryTextArea);
        generatedDictionaryPanel.add(dictionaryContentScrollPane, BorderLayout.CENTER);
        
        // 生成字典操作按钮面板
        JPanel generatedActionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        // 保存按钮
        saveDictionaryButton = new JButton("保存字典");
        saveDictionaryButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveDictionaryToFile();
            }
        });
        generatedActionPanel.add(saveDictionaryButton);
        
        // 使用按钮
        useButton = new JButton("使用该字典");
        useButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedType = promptTypeList.getSelectedValue();
                if (selectedType != null) {
                    // 获取文本区域中的内容，按行分割
                    String content = dictionaryTextArea.getText();
                    String[] lines = content.split("\\n");
                    
                    // 更新字典内容
                    java.util.List<String> entries = new java.util.ArrayList<>();
                    for (String line : lines) {
                        if (!line.trim().isEmpty()) {
                            entries.add(line.trim());
                        }
                    }
                    
                    // 更新字典
                    dictionaryManager.updateDictionary(selectedType, entries);
                    
                    // 设置为当前选中的字典
                    dictionaryManager.setSelectedDictionary(selectedType);
                    
                    JOptionPane.showMessageDialog(FuzzMindTab.this, 
                            "已选择「" + configManager.getPromptName(selectedType) + "」作为Intruder有效载荷\n" +
                            "现在您可以在Intruder中选择「FuzzMind Payload Generator」使用该字典",
                            "FuzzMind", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });
        generatedActionPanel.add(useButton);
        generatedDictionaryPanel.add(generatedActionPanel, BorderLayout.SOUTH);
        
        // 创建保存字典面板
        JPanel savedDictionaryPanel = new JPanel(new BorderLayout());
        
        // 分割面板：左侧是字典列表，右侧是字典内容
        JSplitPane savedDictionarySplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // 左侧字典列表面板
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
        
        // 字典列表操作按钮面板
        JPanel savedDictionaryListButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        deleteSavedDictionaryButton = new JButton("删除");
        deleteSavedDictionaryButton.setEnabled(false);
        deleteSavedDictionaryButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedDictionary = savedDictionaryList.getSelectedValue();
                if (selectedDictionary != null) {
                    int result = JOptionPane.showConfirmDialog(FuzzMindTab.this, 
                            "确定要删除字典「" + selectedDictionary + "」吗？", 
                            "确认删除", 
                            JOptionPane.YES_NO_OPTION);
                    
                    if (result == JOptionPane.YES_OPTION) {
                        // 从字典管理器中删除对应字典
                        dictionaryManager.removeSavedDictionary(selectedDictionary);
                        
                        // 更新列表
                        updateSavedDictionaryList();
                    }
                }
            }
        });
        savedDictionaryListButtonPanel.add(deleteSavedDictionaryButton);
        savedDictionaryListPanel.add(savedDictionaryListButtonPanel, BorderLayout.SOUTH);
        
        // 右侧字典内容面板
        JPanel savedDictionaryContentPanel = new JPanel(new BorderLayout());
        savedDictionaryContentPanel.setBorder(BorderFactory.createTitledBorder("字典内容"));
        
        savedDictionaryTextArea = new JTextArea();
        savedDictionaryTextArea.setLineWrap(true);
        JScrollPane savedDictionaryContentScrollPane = new JScrollPane(savedDictionaryTextArea);
        savedDictionaryContentPanel.add(savedDictionaryContentScrollPane, BorderLayout.CENTER);
        
        // 保存字典操作按钮面板
        JPanel savedDictionaryActionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        // 添加保存更改按钮
        saveSavedDictionaryButton = new JButton("保存更改");
        saveSavedDictionaryButton.setEnabled(false);
        saveSavedDictionaryButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedDictionary = savedDictionaryList.getSelectedValue();
                if (selectedDictionary != null) {
                    // 获取文本区域中的内容，按行分割
                    String content = savedDictionaryTextArea.getText();
                    String[] lines = content.split("\\n");
                    
                    // 更新字典内容
                    java.util.List<String> entries = new java.util.ArrayList<>();
                    for (String line : lines) {
                        if (!line.trim().isEmpty()) {
                            entries.add(line.trim());
                        }
                    }
                    
                    // 保存字典，不去重
                    int count = dictionaryManager.saveDictionaryToFile(selectedDictionary, selectedDictionary, entries, false);
                    
                    // 更新保存字典列表
                    updateSavedDictionaryList();
                    
                    // 提示保存成功
                    JOptionPane.showMessageDialog(FuzzMindTab.this, 
                            "字典更新成功！\n" +
                            "字典名称：" + selectedDictionary + "\n" +
                            "条目数量：" + count,
                            "保存成功", 
                            JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });
        savedDictionaryActionPanel.add(saveSavedDictionaryButton);
        
        useSavedDictionaryButton = new JButton("使用该字典");
        useSavedDictionaryButton.setEnabled(false);
        useSavedDictionaryButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedDictionary = savedDictionaryList.getSelectedValue();
                if (selectedDictionary != null) {
                    // 设置为当前选中的字典
                    dictionaryManager.setSelectedDictionary(selectedDictionary, DictionaryManager.DictionaryType.SAVED);
                    
                    JOptionPane.showMessageDialog(FuzzMindTab.this, 
                            "已选择「" + selectedDictionary + "」作为Intruder有效载荷\n" +
                            "现在您可以在Intruder中选择「FuzzMind Payload Generator」使用该字典",
                            "FuzzMind", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });
        savedDictionaryActionPanel.add(useSavedDictionaryButton);
        savedDictionaryContentPanel.add(savedDictionaryActionPanel, BorderLayout.SOUTH);
        
        // 添加到分割面板
        savedDictionarySplitPane.setLeftComponent(savedDictionaryListPanel);
        savedDictionarySplitPane.setRightComponent(savedDictionaryContentPanel);
        savedDictionarySplitPane.setDividerLocation(200);
        
        savedDictionaryPanel.add(savedDictionarySplitPane, BorderLayout.CENTER);
        
        // 添加两个标签页
        dictionaryTabbedPane.addTab("生成字典", generatedDictionaryPanel);
        dictionaryTabbedPane.addTab("存储字典", savedDictionaryPanel);
        
        // 创建分割面板
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, middlePanel, dictionaryTabbedPane);
        rightSplitPane.setDividerLocation(400);
        
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightSplitPane);
        mainSplitPane.setDividerLocation(200);
        
        add(mainSplitPane, BorderLayout.CENTER);
    }
    
    /**
     * 显示添加提示词类型对话框
     */
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
            
            // 检查是否已存在
            if (configManager.getPromptTypes().contains(key)) {
                JOptionPane.showMessageDialog(this, "提示词类型「" + key + "」已存在", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            // 添加到配置
            configManager.addPromptType(key, name, prompt);
            
            // 添加空字典
            dictionaryManager.addDictionary(key, new java.util.ArrayList<>());
            
            // 更新列表
            updatePromptTypeList();
            
            // 选中新添加的项
            promptTypeList.setSelectedValue(key, true);
            
            JOptionPane.showMessageDialog(this, "提示词类型添加成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * 显示编辑提示词类型对话框
     * @param promptType 提示词类型
     */
    private void showEditPromptTypeDialog(String promptType) {
        JPanel panel = new JPanel(new GridLayout(0, 1));
        
        JPanel keyPanel = new JPanel(new BorderLayout());
        keyPanel.add(new JLabel("提示词类型标识（英文）: "), BorderLayout.WEST);
        JTextField keyField = new JTextField(promptType, 20);
        keyField.setEditable(false); // 不允许修改标识
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
            
            // 更新配置
            configManager.updatePromptType(promptType, name, prompt);
            
            // 更新显示
            displayPromptAndDictionary(promptType);
            
            JOptionPane.showMessageDialog(this, "提示词类型更新成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * 显示配置对话框
     */
    private void showConfigDialog() {
        JPanel panel = new JPanel(new GridLayout(0, 1));
        
        JPanel apiKeyPanel = new JPanel(new BorderLayout());
        apiKeyPanel.add(new JLabel("API密钥: "), BorderLayout.WEST);
        JTextField apiKeyField = new JTextField(configManager.getConfig(ConfigManager.API_KEY), 30);
        apiKeyPanel.add(apiKeyField, BorderLayout.CENTER);
        panel.add(apiKeyPanel);
        
        int result = JOptionPane.showConfirmDialog(this, panel, "配置API密钥", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            configManager.setConfig(ConfigManager.API_KEY, apiKeyField.getText());
            JOptionPane.showMessageDialog(this, "API密钥已保存", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * 更新提示词类型列表
     */
    private void updatePromptTypeList() {
        String selectedType = promptTypeList.getSelectedValue();
        
        promptTypeListModel.clear();
        for (String type : configManager.getPromptTypes()) {
            promptTypeListModel.addElement(type);
        }
        
        // 尝试恢复之前的选择
        if (selectedType != null && promptTypeListModel.contains(selectedType)) {
            promptTypeList.setSelectedValue(selectedType, true);
        }
        // 否则默认选中第一个
        else if (!promptTypeListModel.isEmpty()) {
            promptTypeList.setSelectedIndex(0);
        }
    }
    
    /**
     * 显示提示词和字典内容
     * @param promptType 提示词类型
     */
    private void displayPromptAndDictionary(String promptType) {
        // 显示提示词
        promptTextArea.setText(configManager.getPromptTemplate(promptType));
        
        // 显示字典内容
        List<String> entries = dictionaryManager.getDictionary(promptType);
        StringBuilder sb = new StringBuilder();
        for (String entry : entries) {
            sb.append(entry).append("\n");
        }
        dictionaryTextArea.setText(sb.toString());
    }
    
    /**
     * 生成字典
     */
    private void generateDictionary() {
        // 获取当前选中的提示词类型和提示词内容
        String selectedType = promptTypeList.getSelectedValue();
        String prompt = promptTextArea.getText();
        
        if (selectedType == null) {
            JOptionPane.showMessageDialog(this, "请先选择一个提示词类型", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        // 保存修改后的提示词
        configManager.setPromptTemplate(selectedType, prompt);
        
        // 检查API密钥是否已配置
        String apiKey = configManager.getConfig(ConfigManager.API_KEY);
        if (apiKey == null || apiKey.trim().isEmpty()) {
            int result = JOptionPane.showConfirmDialog(this, 
                    "API密钥未配置，是否现在配置？", 
                    "配置API密钥", 
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
        
        // 显示正在生成的提示
        generateButton.setEnabled(false);
        generateButton.setText("生成中...");
        
        // 创建一个新线程来调用AI生成字典
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // 调用AI生成字典
                    final List<String> generatedPayloads = aiGenerator.generateDictionary(selectedType, prompt);
                    
                    // 在EDT线程中更新UI
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            // 将生成的内容显示在字典内容区域
                            StringBuilder sb = new StringBuilder();
                            for (String payload : generatedPayloads) {
                                sb.append(payload).append("\n");
                            }
                            dictionaryTextArea.setText(sb.toString());
                            
                            // 更新字典
                            dictionaryManager.updateDictionary(selectedType, generatedPayloads);
                            
                            // 恢复按钮状态
                            generateButton.setText("生成字典");
                            generateButton.setEnabled(true);
                            
                            // 提示用户生成完成
                            JOptionPane.showMessageDialog(FuzzMindTab.this, 
                                    "字典生成完成！\n" +
                                    "生成了 " + generatedPayloads.size() + " 个条目\n" +
                                    "您可以直接编辑内容，然后点击「使用该字典」按钮。",
                                    "FuzzMind", JOptionPane.INFORMATION_MESSAGE);
                        }
                    });
                } catch (final Exception e) {
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            generateButton.setText("生成字典");
                            generateButton.setEnabled(true);
                            JOptionPane.showMessageDialog(FuzzMindTab.this, 
                                    "生成失败：" + e.getMessage(),
                                    "错误", JOptionPane.ERROR_MESSAGE);
                        }
                    });
                }
            }
        }).start();
    }
    
    /**
     * 更新保存的字典列表
     */
    private void updateSavedDictionaryList() {
        String selectedDictionary = savedDictionaryList.getSelectedValue();
        
        savedDictionaryListModel.clear();
        for (String name : dictionaryManager.getSavedDictionaryNames()) {
            savedDictionaryListModel.addElement(name);
        }
        
        // 尝试恢复之前的选择
        if (selectedDictionary != null && savedDictionaryListModel.contains(selectedDictionary)) {
            savedDictionaryList.setSelectedValue(selectedDictionary, true);
        }
        // 否则默认选中第一个
        else if (!savedDictionaryListModel.isEmpty()) {
            savedDictionaryList.setSelectedIndex(0);
        }
    }
    
    /**
     * 显示保存的字典
     * @param dictionaryName 字典名称
     */
    private void displaySavedDictionary(String dictionaryName) {
        List<String> entries = dictionaryManager.getDictionary(dictionaryName, DictionaryManager.DictionaryType.SAVED);
        StringBuilder sb = new StringBuilder();
        for (String entry : entries) {
            sb.append(entry).append("\n");
        }
        savedDictionaryTextArea.setText(sb.toString());
    }
    
    /**
     * 保存字典到文件
     */
    private void saveDictionaryToFile() {
        String selectedType = promptTypeList.getSelectedValue();
        if (selectedType == null) {
            JOptionPane.showMessageDialog(this, "请先选择一个提示词类型", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        
        // 获取字典内容
        String content = dictionaryTextArea.getText();
        String[] lines = content.split("\\n");
        
        // 过滤空行
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
        
        // 询问是否去重
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
        
        // 保存字典
        String chineseName = configManager.getPromptName(selectedType);
        int count = dictionaryManager.saveDictionaryToFile(selectedType, chineseName, entries, deduplication);
        
        // 更新保存字典列表
        updateSavedDictionaryList();
        
        // 提示保存成功
        JOptionPane.showMessageDialog(this, 
                "字典保存成功！\n" +
                "字典名称：" + chineseName + "\n" +
                "条目数量：" + count + "\n" +
                "保存位置：~/.config/fuzzMind/" + chineseName + ".txt",
                "保存成功", 
                JOptionPane.INFORMATION_MESSAGE);
    }
} 