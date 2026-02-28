package burp.waf;

public class BypassTechnique {
    
    private String id;
    private String name;
    private String description;
    private int baseSuccessRate;
    private boolean enabled;
    
    public BypassTechnique() {
        this.enabled = true;
    }
    
    public BypassTechnique(String id, String name, int baseSuccessRate) {
        this();
        this.id = id;
        this.name = name;
        this.baseSuccessRate = baseSuccessRate;
    }
    
    public BypassTechnique(String id, String name, String description, int baseSuccessRate) {
        this(id, name, baseSuccessRate);
        this.description = description;
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public int getBaseSuccessRate() {
        return baseSuccessRate;
    }
    
    public void setBaseSuccessRate(int baseSuccessRate) {
        this.baseSuccessRate = Math.max(0, Math.min(100, baseSuccessRate));
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        BypassTechnique that = (BypassTechnique) obj;
        return id != null && id.equals(that.id);
    }
    
    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }
    
    @Override
    public String toString() {
        return "BypassTechnique{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", baseSuccessRate=" + baseSuccessRate +
                '}';
    }
}
