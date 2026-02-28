package burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

public class SearchPanel extends JPanel {
    
    private JTextField searchField;
    private JButton searchButton;
    private JButton clearButton;
    private JLabel resultCountLabel;
    
    private SearchListener searchListener;
    
    public interface SearchListener {
        void onSearch(String keyword);
        void onClear();
    }
    
    public SearchPanel() {
        initComponents();
    }
    
    public void setSearchListener(SearchListener listener) {
        this.searchListener = listener;
    }
    
    private void initComponents() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("搜索过滤"));
        
        JPanel mainPanel = new JPanel(new BorderLayout(5, 0));
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        
        JPanel inputPanel = new JPanel(new BorderLayout(5, 0));
        
        searchField = new JTextField();
        searchField.setToolTipText("输入关键词搜索字典内容");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                onSearchChange();
            }
            
            @Override
            public void removeUpdate(DocumentEvent e) {
                onSearchChange();
            }
            
            @Override
            public void changedUpdate(DocumentEvent e) {
                onSearchChange();
            }
        });
        
        searchField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performSearch();
            }
        });
        
        inputPanel.add(searchField, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        
        searchButton = new JButton("搜索");
        searchButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performSearch();
            }
        });
        buttonPanel.add(searchButton);
        
        clearButton = new JButton("清除");
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                searchField.setText("");
                if (searchListener != null) {
                    searchListener.onClear();
                }
                resultCountLabel.setText("");
            }
        });
        buttonPanel.add(clearButton);
        
        inputPanel.add(buttonPanel, BorderLayout.EAST);
        
        mainPanel.add(inputPanel, BorderLayout.CENTER);
        
        resultCountLabel = new JLabel(" ");
        resultCountLabel.setBorder(new EmptyBorder(0, 5, 0, 0));
        mainPanel.add(resultCountLabel, BorderLayout.SOUTH);
        
        add(mainPanel, BorderLayout.CENTER);
    }
    
    private void onSearchChange() {
        String text = searchField.getText();
        if (text.isEmpty()) {
            if (searchListener != null) {
                searchListener.onClear();
            }
            resultCountLabel.setText("");
        }
    }
    
    private void performSearch() {
        String keyword = searchField.getText().trim();
        if (searchListener != null) {
            searchListener.onSearch(keyword);
        }
    }
    
    public void setResultCount(int count, int total) {
        if (count == total) {
            resultCountLabel.setText(String.format("共 %d 条", total));
        } else {
            resultCountLabel.setText(String.format("找到 %d / %d 条", count, total));
        }
    }
    
    public void setKeyword(String keyword) {
        searchField.setText(keyword);
    }
    
    public String getKeyword() {
        return searchField.getText().trim();
    }
}
