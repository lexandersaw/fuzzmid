package burp.payload;

public class PayloadScore {
    
    private String payload;
    private int overallScore;
    private int versatilityScore;
    private int bypassScore;
    private int stealthScore;
    private int impactScore;
    private String category;
    private int testCount;
    private int successCount;
    private long lastUpdated;
    
    public PayloadScore() {
        this.testCount = 0;
        this.successCount = 0;
        this.lastUpdated = System.currentTimeMillis();
    }
    
    public PayloadScore(String payload, int overallScore) {
        this();
        this.payload = payload;
        this.overallScore = overallScore;
    }
    
    public String getPayload() {
        return payload;
    }
    
    public void setPayload(String payload) {
        this.payload = payload;
    }
    
    public int getOverallScore() {
        return overallScore;
    }
    
    public void setOverallScore(int overallScore) {
        this.overallScore = overallScore;
        this.lastUpdated = System.currentTimeMillis();
    }
    
    public int getVersatilityScore() {
        return versatilityScore;
    }
    
    public void setVersatilityScore(int versatilityScore) {
        this.versatilityScore = versatilityScore;
    }
    
    public int getBypassScore() {
        return bypassScore;
    }
    
    public void setBypassScore(int bypassScore) {
        this.bypassScore = bypassScore;
    }
    
    public int getStealthScore() {
        return stealthScore;
    }
    
    public void setStealthScore(int stealthScore) {
        this.stealthScore = stealthScore;
    }
    
    public int getImpactScore() {
        return impactScore;
    }
    
    public void setImpactScore(int impactScore) {
        this.impactScore = impactScore;
    }
    
    public String getCategory() {
        return category;
    }
    
    public void setCategory(String category) {
        this.category = category;
    }
    
    public int getTestCount() {
        return testCount;
    }
    
    public void setTestCount(int testCount) {
        this.testCount = testCount;
    }
    
    public int getSuccessCount() {
        return successCount;
    }
    
    public void setSuccessCount(int successCount) {
        this.successCount = successCount;
    }
    
    public long getLastUpdated() {
        return lastUpdated;
    }
    
    public void setLastUpdated(long lastUpdated) {
        this.lastUpdated = lastUpdated;
    }
    
    public double getSuccessRate() {
        if (testCount == 0) return 0.0;
        return (double) successCount / testCount * 100;
    }
    
    public void recordTest(boolean success) {
        testCount++;
        if (success) {
            successCount++;
        }
        
        // 根据测试结果调整分数
        if (success && overallScore < 95) {
            overallScore = Math.min(100, overallScore + 1);
        } else if (!success && overallScore > 5) {
            overallScore = Math.max(0, overallScore - 1);
        }
        
        lastUpdated = System.currentTimeMillis();
    }
    
    public String getScoreLevel() {
        if (overallScore >= 90) return "S";
        if (overallScore >= 80) return "A";
        if (overallScore >= 70) return "B";
        if (overallScore >= 60) return "C";
        if (overallScore >= 50) return "D";
        return "E";
    }
    
    @Override
    public String toString() {
        return String.format("PayloadScore{payload='%s', score=%d, level=%s, successRate=%.1f%%}",
                payload, overallScore, getScoreLevel(), getSuccessRate());
    }
}
