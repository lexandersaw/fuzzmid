package burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import burp.dictionary.HistoryManager;
import burp.dictionary.HistoryManager.HistoryEntry;

public class HistoryPanel extends JPanel {
    
    private final HistoryManager historyManager;
    private JList<HistoryEntry> historyList;
    private DefaultListModel<HistoryEntry> historyListModel;
    private JTextArea detailTextArea;
    private JTextArea payloadTextArea;
    private JButton useButton;
    private JButton deleteButton;
    private JButton clearButton;
    
    private HistoryEntry selectedEntry;
    
    public interface HistorySelectionListener {
        void onHistorySelected(HistoryEntry entry);
    }
    
    private HistorySelectionListener selectionListener;
    
    public HistoryPanel(HistoryManager historyManager) {
        this.historyManager = historyManager;
        initComponents();
        loadHistory();
    }
    
    public void setSelectionListener(HistorySelectionListener listener) {
        this.selectionListener = listener;
    }
    
    private void initComponents() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("生成历史"));
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        JPanel listPanel = new JPanel(new BorderLayout());
        
        historyListModel = new DefaultListModel<>();
        historyList = new JList<>(historyListModel);
        historyList.setCellRenderer(new HistoryEntryRenderer());
        historyList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        historyList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    selectedEntry = historyList.getSelectedValue();
                    updateDetail();
                }
            }
        });
        
        JScrollPane listScrollPane = new JScrollPane(historyList);
        listScrollPane.setPreferredSize(new Dimension(250, 0));
        listPanel.add(listScrollPane, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        deleteButton = new JButton("删除");
        deleteButton.setEnabled(false);
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedEntry != null) {
                    int result = JOptionPane.showConfirmDialog(HistoryPanel.this,
                            "确定要删除此历史记录吗？",
                            "确认删除",
                            JOptionPane.YES_NO_OPTION);
                    
                    if (result == JOptionPane.YES_OPTION) {
                        historyManager.deleteHistoryEntry(selectedEntry.getId());
                        loadHistory();
                    }
                }
            }
        });
        buttonPanel.add(deleteButton);
        
        clearButton = new JButton("清空");
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int result = JOptionPane.showConfirmDialog(HistoryPanel.this,
                        "确定要清空所有历史记录吗？",
                        "确认清空",
                        JOptionPane.YES_NO_OPTION);
                
                if (result == JOptionPane.YES_OPTION) {
                    historyManager.clearHistory();
                    loadHistory();
                }
            }
        });
        buttonPanel.add(clearButton);
        
        listPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        JPanel detailPanel = new JPanel(new BorderLayout());
        
        detailTextArea = new JTextArea();
        detailTextArea.setEditable(false);
        detailTextArea.setLineWrap(true);
        detailTextArea.setWrapStyleWord(true);
        JScrollPane detailScrollPane = new JScrollPane(detailTextArea);
        detailScrollPane.setBorder(BorderFactory.createTitledBorder("详情"));
        detailScrollPane.setPreferredSize(new Dimension(0, 150));
        
        payloadTextArea = new JTextArea();
        payloadTextArea.setEditable(false);
        payloadTextArea.setLineWrap(true);
        JScrollPane payloadScrollPane = new JScrollPane(payloadTextArea);
        payloadScrollPane.setBorder(BorderFactory.createTitledBorder("生成的Payload"));
        
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.add(detailScrollPane, BorderLayout.NORTH);
        rightPanel.add(payloadScrollPane, BorderLayout.CENTER);
        
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        useButton = new JButton("使用此Payload");
        useButton.setEnabled(false);
        useButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedEntry != null && selectionListener != null) {
                    selectionListener.onHistorySelected(selectedEntry);
                }
            }
        });
        actionPanel.add(useButton);
        rightPanel.add(actionPanel, BorderLayout.SOUTH);
        
        splitPane.setLeftComponent(listPanel);
        splitPane.setRightComponent(rightPanel);
        splitPane.setDividerLocation(280);
        
        add(splitPane, BorderLayout.CENTER);
    }
    
    private void loadHistory() {
        historyListModel.clear();
        
        List<HistoryEntry> entries = historyManager.getAllHistoryEntries();
        
        for (int i = entries.size() - 1; i >= 0; i--) {
            historyListModel.addElement(entries.get(i));
        }
        
        selectedEntry = null;
        updateDetail();
    }
    
    private void updateDetail() {
        if (selectedEntry != null) {
            StringBuilder detail = new StringBuilder();
            detail.append("时间: ").append(selectedEntry.getFormattedTime()).append("\n");
            detail.append("类型: ").append(selectedEntry.getPromptType()).append("\n");
            detail.append("模型: ").append(selectedEntry.getModel()).append("\n");
            detail.append("Payload数量: ").append(selectedEntry.getPayloadCount()).append("\n");
            detail.append("\n提示词:\n").append(selectedEntry.getPrompt());
            
            detailTextArea.setText(detail.toString());
            
            StringBuilder payloads = new StringBuilder();
            for (String payload : selectedEntry.getGeneratedPayloads()) {
                payloads.append(payload).append("\n");
            }
            payloadTextArea.setText(payloads.toString());
            
            useButton.setEnabled(true);
            deleteButton.setEnabled(true);
        } else {
            detailTextArea.setText("");
            payloadTextArea.setText("");
            useButton.setEnabled(false);
            deleteButton.setEnabled(false);
        }
    }
    
    public void refresh() {
        loadHistory();
    }
    
    private static class HistoryEntryRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, 
                                                       int index, boolean isSelected, 
                                                       boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (value instanceof HistoryEntry) {
                HistoryEntry entry = (HistoryEntry) value;
                String text = String.format("[%s] %s (%d payloads)",
                        entry.getFormattedTime(),
                        entry.getPromptType(),
                        entry.getPayloadCount());
                setText(text);
            }
            
            return this;
        }
    }
}
