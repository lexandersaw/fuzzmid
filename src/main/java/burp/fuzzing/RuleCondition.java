package burp.fuzzing;

import java.util.Map;
import java.util.regex.Pattern;

public class RuleCondition {
    
    private String field;
    private Operator operator;
    private String value;
    private boolean caseSensitive;
    
    public enum Operator {
        EQUALS,             // 等于
        NOT_EQUALS,         // 不等于
        CONTAINS,           // 包含
        NOT_CONTAINS,       // 不包含
        STARTS_WITH,        // 开头为
        ENDS_WITH,          // 结尾为
        MATCHES_REGEX,      // 正则匹配
        GREATER_THAN,       // 大于
        LESS_THAN,          // 小于
        IN_LIST,            // 在列表中
        NOT_IN_LIST,        // 不在列表中
        IS_EMPTY,           // 为空
        IS_NOT_EMPTY        // 不为空
    }
    
    public RuleCondition() {
        this.caseSensitive = false;
    }
    
    public RuleCondition(String field, Operator operator, String value) {
        this();
        this.field = field;
        this.operator = operator;
        this.value = value;
    }
    
    public boolean evaluate(FuzzingContext context) {
        if (context == null || field == null || operator == null) {
            return false;
        }
        
        String fieldValue = context.getFieldValue(field);
        
        if (fieldValue == null) {
            fieldValue = "";
        }
        
        String compareValue = value != null ? value : "";
        
        if (!caseSensitive) {
            fieldValue = fieldValue.toLowerCase();
            compareValue = compareValue.toLowerCase();
        }
        
        switch (operator) {
            case EQUALS:
                return fieldValue.equals(compareValue);
                
            case NOT_EQUALS:
                return !fieldValue.equals(compareValue);
                
            case CONTAINS:
                return fieldValue.contains(compareValue);
                
            case NOT_CONTAINS:
                return !fieldValue.contains(compareValue);
                
            case STARTS_WITH:
                return fieldValue.startsWith(compareValue);
                
            case ENDS_WITH:
                return fieldValue.endsWith(compareValue);
                
            case MATCHES_REGEX:
                try {
                    Pattern pattern = Pattern.compile(compareValue, caseSensitive ? 0 : Pattern.CASE_INSENSITIVE);
                    return pattern.matcher(fieldValue).find();
                } catch (Exception e) {
                    return false;
                }
                
            case GREATER_THAN:
                try {
                    return Double.parseDouble(fieldValue) > Double.parseDouble(compareValue);
                } catch (NumberFormatException e) {
                    return fieldValue.compareTo(compareValue) > 0;
                }
                
            case LESS_THAN:
                try {
                    return Double.parseDouble(fieldValue) < Double.parseDouble(compareValue);
                } catch (NumberFormatException e) {
                    return fieldValue.compareTo(compareValue) < 0;
                }
                
            case IN_LIST:
                String[] listItems = compareValue.split(",");
                for (String item : listItems) {
                    if (fieldValue.equals(item.trim())) {
                        return true;
                    }
                }
                return false;
                
            case NOT_IN_LIST:
                listItems = compareValue.split(",");
                for (String item : listItems) {
                    if (fieldValue.equals(item.trim())) {
                        return false;
                    }
                }
                return true;
                
            case IS_EMPTY:
                return fieldValue.isEmpty();
                
            case IS_NOT_EMPTY:
                return !fieldValue.isEmpty();
                
            default:
                return false;
        }
    }
    
    public String getField() {
        return field;
    }
    
    public void setField(String field) {
        this.field = field;
    }
    
    public Operator getOperator() {
        return operator;
    }
    
    public void setOperator(Operator operator) {
        this.operator = operator;
    }
    
    public String getValue() {
        return value;
    }
    
    public void setValue(String value) {
        this.value = value;
    }
    
    public boolean isCaseSensitive() {
        return caseSensitive;
    }
    
    public void setCaseSensitive(boolean caseSensitive) {
        this.caseSensitive = caseSensitive;
    }
    
    @Override
    public String toString() {
        return "RuleCondition{" +
                "field='" + field + '\'' +
                ", operator=" + operator +
                ", value='" + value + '\'' +
                '}';
    }
}
