package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class BurpExtender implements IBurpExtender, IIntruderPayloadGeneratorFactory, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private FuzzMindTab fuzzMindTab;
    private DictionaryManager dictionaryManager;
    private ConfigManager configManager;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 保存回调对象
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        // 设置扩展名称
        callbacks.setExtensionName("FuzzMind");
        
        // 初始化配置管理器
        this.configManager = new ConfigManager(callbacks);
        
        // 初始化字典管理器
        this.dictionaryManager = new DictionaryManager();
        
        // 初始化预设字典
        initializeDefaultDictionaries();
        
        // 加载保存的字典
        dictionaryManager.loadSavedDictionaries(configManager);
        
        // 创建自定义UI标签页
        SwingUtilities.invokeLater(() -> {
            fuzzMindTab = new FuzzMindTab(callbacks, dictionaryManager, configManager);
            callbacks.addSuiteTab(BurpExtender.this);
        });
        
        // 注册Intruder有效载荷生成器
        callbacks.registerIntruderPayloadGeneratorFactory(this);

        // 插件加载完成后，在Output中输出使用说明
        callbacks.printOutput("----------------------------------------");
        callbacks.printOutput("FuzzMind 字典管理器已加载!");
        callbacks.printOutput("----------------------------------------");
        callbacks.printOutput("使用说明:");
        callbacks.printOutput("1. 在左侧选择提示词类型，可以添加、编辑或删除提示词类型");
        callbacks.printOutput("2. 在中间区域可以查看和修改提示词");
        callbacks.printOutput("3. 点击「生成字典」按钮生成字典内容");
        callbacks.printOutput("4. 在右侧可以查看和编辑生成的字典内容，并可以保存到本地");
        callbacks.printOutput("5. 在「存储字典」标签页中可以管理已保存的字典");
        callbacks.printOutput("6. 点击「使用该字典」后，在Burp Intruder中选择「FuzzMind Payload Generator」即可使用该字典");
        callbacks.printOutput("7. 配置文件和字典存储位置：~/.config/fuzzMind/");
        callbacks.printOutput("----------------------------------------");
        callbacks.printOutput("https://github.com/Conan924/AIPentestKit/blob/main/FuzzMind");
        callbacks.printOutput("----------------------------------------");
    }
    
    private void initializeDefaultDictionaries() {
        // 为每种提示词类型创建一个空字典
        for (String promptType : configManager.getPromptTypes()) {
            dictionaryManager.addDictionary(promptType, new ArrayList<>());
        }
        
        // // 添加一些示例数据到中国姓名字典
        // List<String> cnPasswords = new ArrayList<>();
        // cnPasswords.add("123456");
        // cnPasswords.add("123456789");
        // cnPasswords.add("888888");
        // cnPasswords.add("password");
        // cnPasswords.add("qwerty");
        // cnPasswords.add("12345678");
        // cnPasswords.add("111111");
        // cnPasswords.add("1234567890");
        // dictionaryManager.updateDictionary("cn_passwords", cnPasswords);
    }

    @Override
    public String getGeneratorName() {
        return "FuzzMind Payload Generator";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        // 获取当前选中的字典内容，支持生成字典和保存字典
        List<String> selectedDictionary = dictionaryManager.getSelectedDictionary();
        
        // 如果字典为空，则显示警告
        if (selectedDictionary.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(null, 
                        "当前没有选中字典或字典内容为空！\n" +
                        "请先在FuzzMind标签页中选择一个字典。", 
                        "FuzzMind警告", 
                        JOptionPane.WARNING_MESSAGE);
            });
        }
        
        return new FuzzPayloadGenerator(selectedDictionary);
    }
    
    // ITab接口实现
    @Override
    public String getTabCaption() {
        return "FuzzMind";
    }

    @Override
    public JComponent getUiComponent() {
        return fuzzMindTab;
    }
}
