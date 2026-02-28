package burp.payload;

public class EvaluationResult {
    
    private String payload;
    private int score;
    private String description;
    private double versatilityScore;
    private double bypassScore;
    private double stealthScore;
    private double impactScore;
    
    public EvaluationResult() {
        this.score = 0;
        this.description = "";
        this.versatilityScore = 0;
        this.bypassScore = 0;
        this.stealthScore = 0;
        this.impactScore = 0;
    }
    
    public EvaluationResult(String payload, int score, String description) {
        this.payload = payload;
        this.score = score;
        this.description = description;
    }
    
    public String getPayload() {
        return payload;
    }
    
    public void setPayload(String payload) {
        this.payload = payload;
    }
    
    public int getScore() {
        return score;
    }
    
    public void setScore(int score) {
        this.score = score;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public double getVersatilityScore() {
        return versatilityScore;
    }
    
    public void setVersatilityScore(double versatilityScore) {
        this.versatilityScore = versatilityScore;
    }
    
    public double getBypassScore() {
        return bypassScore;
    }
    
    public void setBypassScore(double bypassScore) {
        this.bypassScore = bypassScore;
    }
    
    public double getStealthScore() {
        return stealthScore;
    }
    
    public void setStealthScore(double stealthScore) {
        this.stealthScore = stealthScore;
    }
    
    public double getImpactScore() {
        return impactScore;
    }
    
    public void setImpactScore(double impactScore) {
        this.impactScore = impactScore;
    }
    
    public String getScoreLevel() {
        if (score >= 90) return "极高";
        if (score >= 80) return "高";
        if (score >= 70) return "中高";
        if (score >= 60) return "中";
        if (score >= 50) return "中低";
        return "低";
    }
    
    public String getFormattedOutput() {
        return String.format("[%d分] %s - %s", score, payload, description);
    }
    
    @Override
    public String toString() {
        return getFormattedOutput();
    }
}
