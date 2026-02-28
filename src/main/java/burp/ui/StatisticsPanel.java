package burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.Map;

import burp.dictionary.EnhancedDictionaryManager.DictionaryStatistics;

public class StatisticsPanel extends JPanel {
    
    private JLabel totalCountLabel;
    private JLabel uniqueCountLabel;
    private JLabel minLengthLabel;
    private JLabel maxLengthLabel;
    private JLabel avgLengthLabel;
    private JTextArea distributionArea;
    
    public StatisticsPanel() {
        initComponents();
    }
    
    private void initComponents() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("字典统计"));
        
        JPanel infoPanel = new JPanel(new GridBagLayout());
        infoPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        gbc.gridx = 0; gbc.gridy = 0;
        infoPanel.add(new JLabel("总条目:"), gbc);
        gbc.gridx = 1;
        totalCountLabel = new JLabel("-");
        totalCountLabel.setFont(totalCountLabel.getFont().deriveFont(Font.BOLD));
        infoPanel.add(totalCountLabel, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1;
        infoPanel.add(new JLabel("唯一条目:"), gbc);
        gbc.gridx = 1;
        uniqueCountLabel = new JLabel("-");
        uniqueCountLabel.setFont(uniqueCountLabel.getFont().deriveFont(Font.BOLD));
        infoPanel.add(uniqueCountLabel, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2;
        infoPanel.add(new JLabel("最小长度:"), gbc);
        gbc.gridx = 1;
        minLengthLabel = new JLabel("-");
        infoPanel.add(minLengthLabel, gbc);
        
        gbc.gridx = 0; gbc.gridy = 3;
        infoPanel.add(new JLabel("最大长度:"), gbc);
        gbc.gridx = 1;
        maxLengthLabel = new JLabel("-");
        infoPanel.add(maxLengthLabel, gbc);
        
        gbc.gridx = 0; gbc.gridy = 4;
        infoPanel.add(new JLabel("平均长度:"), gbc);
        gbc.gridx = 1;
        avgLengthLabel = new JLabel("-");
        infoPanel.add(avgLengthLabel, gbc);
        
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        infoPanel.add(new JSeparator(), gbc);
        
        gbc.gridx = 0; gbc.gridy = 6; gbc.gridwidth = 2;
        infoPanel.add(new JLabel("长度分布:"), gbc);
        
        gbc.gridx = 0; gbc.gridy = 7; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0; gbc.weighty = 1.0;
        distributionArea = new JTextArea(8, 20);
        distributionArea.setEditable(false);
        distributionArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane scrollPane = new JScrollPane(distributionArea);
        infoPanel.add(scrollPane, gbc);
        
        add(infoPanel, BorderLayout.CENTER);
    }
    
    public void updateStatistics(DictionaryStatistics stats) {
        if (stats == null) {
            clearStatistics();
            return;
        }
        
        totalCountLabel.setText(String.valueOf(stats.getTotalCount()));
        uniqueCountLabel.setText(String.valueOf(stats.getUniqueCount()));
        minLengthLabel.setText(String.valueOf(stats.getMinLength()));
        maxLengthLabel.setText(String.valueOf(stats.getMaxLength()));
        avgLengthLabel.setText(String.format("%.2f", stats.getAvgLength()));
        
        StringBuilder dist = new StringBuilder();
        Map<Integer, Integer> lengthDist = stats.getLengthDistribution();
        if (lengthDist != null && !lengthDist.isEmpty()) {
            dist.append("长度  数量  占比\n");
            dist.append("----  ----  ----\n");
            
            int total = stats.getTotalCount();
            lengthDist.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .limit(20)
                .forEach(e -> {
                    double percent = (e.getValue() * 100.0) / total;
                    dist.append(String.format("%4d  %4d  %4.1f%%\n", 
                            e.getKey(), e.getValue(), percent));
                });
            
            if (lengthDist.size() > 20) {
                dist.append("... (更多分布省略)\n");
            }
        }
        
        Map<Character, Integer> firstCharDist = stats.getFirstCharDistribution();
        if (firstCharDist != null && !firstCharDist.isEmpty()) {
            dist.append("\n首字符分布:\n");
            firstCharDist.entrySet().stream()
                .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
                .limit(10)
                .forEach(e -> {
                    double percent = (e.getValue() * 100.0) / stats.getTotalCount();
                    dist.append(String.format("'%s': %d (%.1f%%)\n", 
                            e.getKey(), e.getValue(), percent));
                });
        }
        
        distributionArea.setText(dist.toString());
    }
    
    public void clearStatistics() {
        totalCountLabel.setText("-");
        uniqueCountLabel.setText("-");
        minLengthLabel.setText("-");
        maxLengthLabel.setText("-");
        avgLengthLabel.setText("-");
        distributionArea.setText("");
    }
}
