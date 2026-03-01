package burp.workflow;

import java.util.ArrayList;
import java.util.List;

public class WorkflowTemplate {
    
    private String id;
    private String name;
    private String description;
    private List<WorkflowStep> steps;
    private boolean enabled;
    
    public WorkflowTemplate() {
        this.steps = new ArrayList<>();
        this.enabled = true;
    }
    
    public WorkflowTemplate(String id, String name) {
        this();
        this.id = id;
        this.name = name;
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
    
    public List<WorkflowStep> getSteps() {
        return new ArrayList<>(steps);
    }
    
    public void setSteps(List<WorkflowStep> steps) {
        this.steps = steps != null ? new ArrayList<>(steps) : new ArrayList<>();
    }
    
    public void addStep(WorkflowStep step) {
        if (step != null) {
            steps.add(step);
        }
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public static WorkflowTemplate createDefaultTemplate() {
        WorkflowTemplate template = new WorkflowTemplate("default", "默认测试工作流");
        template.setDescription("一键执行完整的渗透测试工作流");
        
        WorkflowStep step1 = new WorkflowStep("analyze_context", "分析请求上下文");
        step1.setDescription("分析HTTP请求，识别技术栈和参数");
        
        WorkflowStep step2 = new WorkflowStep("detect_waf", "检测WAF");
        step2.setDescription("检测目标站点是否使用WAF");
        
        WorkflowStep step3 = new WorkflowStep("suggest_vuln", "推荐漏洞类型");
        step3.setDescription("根据上下文推荐可能的漏洞类型");
        
        WorkflowStep step4 = new WorkflowStep("generate_payloads", "生成Payload");
        step4.setDescription("AI生成针对性Payload");
        
        WorkflowStep step5 = new WorkflowStep("mutate_payloads", "变异Payload");
        step5.setDescription("应用变异规则生成变体");
        
        template.addStep(step1);
        template.addStep(step2);
        template.addStep(step3);
        template.addStep(step4);
        template.addStep(step5);
        
        return template;
    }
}
