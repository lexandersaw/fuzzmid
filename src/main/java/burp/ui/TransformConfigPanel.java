package burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import burp.payload.PayloadTransformer;
import burp.payload.PayloadTransformerFactory;

public class TransformConfigPanel extends JPanel {
    
    private JComboBox<String> encodingCombo;
    private JComboBox<String> caseCombo;
    private JComboBox<String> wrapCombo;
    private JTextField prefixField;
    private JTextField suffixField;
    private JCheckBox enableEncodingCheck;
    private JCheckBox enableCaseCheck;
    private JCheckBox enableWrapCheck;
    private JCheckBox enablePrefixCheck;
    private JCheckBox enableSuffixCheck;
    private JCheckBox generateVariantsCheck;
    
    public TransformConfigPanel() {
        initComponents();
    }
    
    private void initComponents() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Payload变换设置"));
        
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        int row = 0;
        
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 3;
        generateVariantsCheck = new JCheckBox("生成所有编码变体（可能产生大量payload）");
        mainPanel.add(generateVariantsCheck, gbc);
        
        row++;
        gbc.gridwidth = 1;
        
        gbc.gridx = 0; gbc.gridy = row;
        enableEncodingCheck = new JCheckBox("编码变换:");
        mainPanel.add(enableEncodingCheck, gbc);
        
        gbc.gridx = 1; gbc.gridy = row;
        encodingCombo = new JComboBox<>();
        for (PayloadTransformer t : PayloadTransformerFactory.getEncodingTransformers()) {
            encodingCombo.addItem(t.getName());
        }
        mainPanel.add(encodingCombo, gbc);
        
        gbc.gridx = 2; gbc.gridy = row;
        JLabel encLabel = new JLabel("(URL/Base64/HTML等)");
        encLabel.setFont(encLabel.getFont().deriveFont(Font.ITALIC, 10f));
        mainPanel.add(encLabel, gbc);
        
        row++;
        
        gbc.gridx = 0; gbc.gridy = row;
        enableCaseCheck = new JCheckBox("大小写变换:");
        mainPanel.add(enableCaseCheck, gbc);
        
        gbc.gridx = 1; gbc.gridy = row;
        caseCombo = new JComboBox<>();
        for (PayloadTransformer t : PayloadTransformerFactory.getCaseTransformers()) {
            caseCombo.addItem(t.getName());
        }
        mainPanel.add(caseCombo, gbc);
        
        row++;
        
        gbc.gridx = 0; gbc.gridy = row;
        enableWrapCheck = new JCheckBox("包装变换:");
        mainPanel.add(enableWrapCheck, gbc);
        
        gbc.gridx = 1; gbc.gridy = row;
        wrapCombo = new JComboBox<>();
        for (PayloadTransformer t : PayloadTransformerFactory.getWrapTransformers()) {
            wrapCombo.addItem(t.getName());
        }
        mainPanel.add(wrapCombo, gbc);
        
        row++;
        
        gbc.gridx = 0; gbc.gridy = row;
        enablePrefixCheck = new JCheckBox("添加前缀:");
        mainPanel.add(enablePrefixCheck, gbc);
        
        gbc.gridx = 1; gbc.gridy = row;
        prefixField = new JTextField(15);
        prefixField.setEnabled(false);
        mainPanel.add(prefixField, gbc);
        
        row++;
        
        gbc.gridx = 0; gbc.gridy = row;
        enableSuffixCheck = new JCheckBox("添加后缀:");
        mainPanel.add(enableSuffixCheck, gbc);
        
        gbc.gridx = 1; gbc.gridy = row;
        suffixField = new JTextField(15);
        suffixField.setEnabled(false);
        mainPanel.add(suffixField, gbc);
        
        enablePrefixCheck.addActionListener(e -> prefixField.setEnabled(enablePrefixCheck.isSelected()));
        enableSuffixCheck.addActionListener(e -> suffixField.setEnabled(enableSuffixCheck.isSelected()));
        
        add(mainPanel, BorderLayout.CENTER);
    }
    
    public List<PayloadTransformer> getTransformers() {
        List<PayloadTransformer> transformers = new ArrayList<>();
        
        if (enableEncodingCheck.isSelected()) {
            int index = encodingCombo.getSelectedIndex();
            transformers.add(PayloadTransformerFactory.getEncodingTransformers().get(index));
        }
        
        if (enableCaseCheck.isSelected()) {
            int index = caseCombo.getSelectedIndex();
            transformers.add(PayloadTransformerFactory.getCaseTransformers().get(index));
        }
        
        if (enableWrapCheck.isSelected()) {
            int index = wrapCombo.getSelectedIndex();
            transformers.add(PayloadTransformerFactory.getWrapTransformers().get(index));
        }
        
        if (enablePrefixCheck.isSelected() && !prefixField.getText().isEmpty()) {
            transformers.add(new AddPrefixTransformerWrapper(prefixField.getText()));
        }
        
        if (enableSuffixCheck.isSelected() && !suffixField.getText().isEmpty()) {
            transformers.add(new AddSuffixTransformerWrapper(suffixField.getText()));
        }
        
        return transformers;
    }
    
    public boolean isGenerateVariants() {
        return generateVariantsCheck.isSelected();
    }
    
    private static class AddPrefixTransformerWrapper implements PayloadTransformer {
        private final String prefix;
        
        public AddPrefixTransformerWrapper(String prefix) {
            this.prefix = prefix;
        }
        
        @Override
        public String transform(String payload) {
            return prefix + payload;
        }
        
        @Override
        public String getName() {
            return "添加前缀";
        }
        
        @Override
        public String getDescription() {
            return "在Payload前添加: " + prefix;
        }
    }
    
    private static class AddSuffixTransformerWrapper implements PayloadTransformer {
        private final String suffix;
        
        public AddSuffixTransformerWrapper(String suffix) {
            this.suffix = suffix;
        }
        
        @Override
        public String transform(String payload) {
            return payload + suffix;
        }
        
        @Override
        public String getName() {
            return "添加后缀";
        }
        
        @Override
        public String getDescription() {
            return "在Payload后添加: " + suffix;
        }
    }
}
