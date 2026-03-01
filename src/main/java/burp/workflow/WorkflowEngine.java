package burp.workflow;

import burp.AIGenerator;
import burp.ConfigManager;
import burp.DictionaryManager;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.payload.PayloadMutator;
import burp.util.ContextAnalyzer;
import burp.util.ContextAnalyzer.RequestContext;
import burp.waf.WAFDetector;
import burp.waf.WAFSignature.DetectionResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class WorkflowEngine {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final AIGenerator aiGenerator;
    private final DictionaryManager dictionaryManager;
    private final ConfigManager configManager;
    private final WAFDetector wafDetector;
    private final PayloadMutator payloadMutator;
    private final ContextAnalyzer contextAnalyzer;
    
    private WorkflowTemplate template;
    private WorkflowContext currentContext;
    private WorkflowResult currentResult;
    private boolean isRunning;
    
    public WorkflowEngine(IBurpExtenderCallbacks callbacks, AIGenerator aiGenerator,
                          DictionaryManager dictionaryManager, ConfigManager configManager) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.aiGenerator = aiGenerator;
        this.dictionaryManager = dictionaryManager;
        this.configManager = configManager;
        this.wafDetector = new WAFDetector();
        this.payloadMutator = new PayloadMutator();
        this.contextAnalyzer = new ContextAnalyzer(helpers);
        this.template = WorkflowTemplate.createDefaultTemplate();
        this.isRunning = false;
    }
    
    public WorkflowResult execute(IHttpRequestResponse message) {
        if (isRunning) {
            return new WorkflowResult(false, "工作流正在执行中");
        }
        
        isRunning = true;
        long startTime = System.currentTimeMillis();
        
        try {
            currentContext = new WorkflowContext();
            currentResult = new WorkflowResult();
            currentResult.setTotalSteps(template.getSteps().size());
            
            int completedSteps = 0;
            
            for (WorkflowStep step : template.getSteps()) {
                step.setStatus(WorkflowStep.StepStatus.RUNNING);
                callbacks.printOutput("[FuzzMind Workflow] 执行步骤: " + step.getName());
                
                try {
                    executeStep(step, message);
                    step.setStatus(WorkflowStep.StepStatus.COMPLETED);
                    completedSteps++;
                    currentResult.setCompletedSteps(completedSteps);
                } catch (Exception e) {
                    step.setStatus(WorkflowStep.StepStatus.FAILED);
                    step.setError(e.getMessage());
                    callbacks.printError("[FuzzMind Workflow] 步骤失败: " + step.getName() + " - " + e.getMessage());
                }
            }
            
            currentResult.setSuccess(true);
            currentResult.setMessage("工作流执行完成");
            currentResult.setContext(currentContext);
            
        } catch (Exception e) {
            currentResult.setSuccess(false);
            currentResult.setMessage("工作流执行失败: " + e.getMessage());
            callbacks.printError("[FuzzMind Workflow] " + e.getMessage());
        } finally {
            currentResult.setExecutionTimeMs(System.currentTimeMillis() - startTime);
            isRunning = false;
        }
        
        return currentResult;
    }
    
    private void executeStep(WorkflowStep step, IHttpRequestResponse message) throws Exception {
        String stepId = step.getId();
        
        switch (stepId) {
            case "analyze_context":
                executeContextAnalysis(message);
                break;
            case "detect_waf":
                executeWAFDetection(message);
                break;
            case "suggest_vuln":
                executeVulnSuggestion(message);
                break;
            case "generate_payloads":
                executePayloadGeneration(message);
                break;
            case "mutate_payloads":
                executePayloadMutation();
                break;
            default:
                step.setStatus(WorkflowStep.StepStatus.SKIPPED);
        }
    }
    
    private void executeContextAnalysis(IHttpRequestResponse message) {
        RequestContext context = contextAnalyzer.analyzeRequest(message);
        
        currentContext.setTargetUrl(context.getUrl());
        currentContext.setRequestMethod(context.getMethod());
        currentContext.setRequestPath(context.getPath());
        currentContext.setContentType(context.getContentType());
        currentContext.setTechnologies(context.getTechnologies());
        currentContext.setParameters(context.getParameters());
        currentContext.setRequestBody(context.getRequestBody());
        
        StringBuilder result = new StringBuilder();
        result.append("技术栈: ").append(String.join(", ", context.getTechnologies())).append("\n");
        result.append("参数: ").append(String.join(", ", context.getParameters()));
        
        callbacks.printOutput("[FuzzMind Workflow] 上下文分析完成:\n" + result);
    }
    
    private void executeWAFDetection(IHttpRequestResponse message) {
        RequestContext context = contextAnalyzer.analyzeRequest(message);
        
        Map<String, String> headers = new java.util.LinkedHashMap<>();
        if (context.getServerHeader() != null) {
            headers.put("Server", context.getServerHeader());
        }
        if (context.getPoweredBy() != null) {
            headers.put("X-Powered-By", context.getPoweredBy());
        }
        
        String responseBody = context.getResponseBody() != null ? context.getResponseBody() : "";
        
        List<DetectionResult> results = wafDetector.detectAll(headers, responseBody, 200);
        
        if (!results.isEmpty()) {
            currentContext.setDetectedWAF(results.get(0).getWafName());
            callbacks.printOutput("[FuzzMind Workflow] 检测到WAF: " + results.get(0).getWafName());
        } else {
            currentContext.setDetectedWAF("无");
            callbacks.printOutput("[FuzzMind Workflow] 未检测到WAF");
        }
    }
    
    private void executeVulnSuggestion(IHttpRequestResponse message) {
        RequestContext context = contextAnalyzer.analyzeRequest(message);
        String suggestedType = contextAnalyzer.suggestVulnType(context);
        
        currentContext.setSuggestedVulnType(suggestedType);
        callbacks.printOutput("[FuzzMind Workflow] 推荐漏洞类型: " + suggestedType);
    }
    
    private void executePayloadGeneration(IHttpRequestResponse message) throws Exception {
        if (!aiGenerator.isConfigured()) {
            throw new Exception("API Key 未配置");
        }
        
        String vulnType = currentContext.getSuggestedVulnType();
        List<String> payloads = aiGenerator.generateContextAwarePayload(
            message, null, vulnType);
        
        currentContext.setGeneratedPayloads(payloads);
        
        String dictName = "workflow_" + (vulnType != null ? vulnType : "auto");
        dictionaryManager.addDictionary(dictName, payloads);
        
        callbacks.printOutput("[FuzzMind Workflow] 生成 " + payloads.size() + " 个Payload");
    }
    
    private void executePayloadMutation() {
        List<String> originalPayloads = currentContext.getGeneratedPayloads();
        
        if (originalPayloads == null || originalPayloads.isEmpty()) {
            callbacks.printOutput("[FuzzMind Workflow] 无Payload可变异");
            return;
        }
        
        List<String> mutatedPayloads = payloadMutator.mutateList(originalPayloads, 1);
        
        currentContext.addGeneratedPayloads(mutatedPayloads);
        
        callbacks.printOutput("[FuzzMind Workflow] 变异生成 " + mutatedPayloads.size() + " 个Payload");
    }
    
    public void setTemplate(WorkflowTemplate template) {
        this.template = template;
    }
    
    public WorkflowTemplate getTemplate() {
        return template;
    }
    
    public boolean isRunning() {
        return isRunning;
    }
    
    public WorkflowContext getCurrentContext() {
        return currentContext;
    }
    
    public WorkflowResult getCurrentResult() {
        return currentResult;
    }
}
