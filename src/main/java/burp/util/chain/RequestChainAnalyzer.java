package burp.util.chain;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RequestChainAnalyzer {
    
    private final IExtensionHelpers helpers;
    
    public RequestChainAnalyzer(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }
    
    public ChainAnalysisResult analyzeRequests(List<IHttpRequestResponse> messages) {
        ChainAnalysisResult result = new ChainAnalysisResult();
        
        if (messages == null || messages.isEmpty()) {
            return result;
        }
        
        analyzeSessionDependencies(messages, result);
        analyzeTokenDependencies(messages, result);
        analyzeParameterDependencies(messages, result);
        analyzeSequencePatterns(messages, result);
        
        return result;
    }
    
    private void analyzeSessionDependencies(List<IHttpRequestResponse> messages, ChainAnalysisResult result) {
        Map<String, List<Integer>> sessionValues = new LinkedHashMap<>();
        
        for (int i = 0; i < messages.size(); i++) {
            IHttpRequestResponse message = messages.get(i);
            if (message.getResponse() != null) {
                String response = new String(message.getResponse());
                
                Pattern cookiePattern = Pattern.compile("Set-Cookie:\\s*([^;=]+)=([^;]*)", Pattern.CASE_INSENSITIVE);
                Matcher matcher = cookiePattern.matcher(response);
                
                while (matcher.find()) {
                    String cookieName = matcher.group(1).trim();
                    String cookieValue = matcher.group(2).trim();
                    
                    sessionValues.computeIfAbsent(cookieName, k -> new ArrayList<>()).add(i);
                    result.addSessionValue(cookieName, cookieValue, i);
                }
            }
        }
        
        for (Map.Entry<String, List<Integer>> entry : sessionValues.entrySet()) {
            if (entry.getValue().size() > 1) {
                result.addSessionDependency(entry.getKey(), entry.getValue());
            }
        }
    }
    
    private void analyzeTokenDependencies(List<IHttpRequestResponse> messages, ChainAnalysisResult result) {
        Map<String, List<Integer>> tokenUsages = new LinkedHashMap<>();
        
        for (int i = 0; i < messages.size(); i++) {
            IHttpRequestResponse message = messages.get(i);
            
            if (message.getRequest() != null) {
                String request = new String(message.getRequest());
                
                // Authorization: Bearer xxx
                Pattern bearerPattern = Pattern.compile("Authorization:\\s*Bearer\\s+([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
                Matcher bearerMatcher = bearerPattern.matcher(request);
                if (bearerMatcher.find()) {
                    String token = bearerMatcher.group(1).trim();
                    tokenUsages.computeIfAbsent(token, k -> new ArrayList<>()).add(i);
                }
                
                // X-Token: xxx
                Pattern tokenPattern = Pattern.compile("X-Token:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
                Matcher tokenMatcher = tokenPattern.matcher(request);
                if (tokenMatcher.find()) {
                    String token = tokenMatcher.group(1).trim();
                    tokenUsages.computeIfAbsent(token, k -> new ArrayList<>()).add(i);
                }
            }
        }
        
        for (Map.Entry<String, List<Integer>> entry : tokenUsages.entrySet()) {
            if (entry.getValue().size() > 1) {
                result.addTokenDependency(entry.getKey(), entry.getValue());
            }
        }
    }
    
    private void analyzeParameterDependencies(List<IHttpRequestResponse> messages, ChainAnalysisResult result) {
        Map<String, List<Integer>> paramUsages = new LinkedHashMap<>();
        
        for (int i = 0; i < messages.size(); i++) {
            IHttpRequestResponse message = messages.get(i);
            
            if (message.getRequest() != null) {
                String request = new String(message.getRequest());
                
                // URL 参数
                Pattern urlParamPattern = Pattern.compile("[?&]([^=]+)=([^&\\s]+)");
                Matcher urlMatcher = urlParamPattern.matcher(request);
                while (urlMatcher.find()) {
                    String paramName = urlMatcher.group(1);
                    String paramValue = urlMatcher.group(2);
                    
                    String key = paramName + "=" + paramValue;
                    paramUsages.computeIfAbsent(key, k -> new ArrayList<>()).add(i);
                }
                
                // Body 参数
                int bodyStart = request.indexOf("\r\n\r\n");
                if (bodyStart > 0) {
                    String body = request.substring(bodyStart + 4);
                    Pattern bodyParamPattern = Pattern.compile("([^=]+)=([^&]+)");
                    Matcher bodyMatcher = bodyParamPattern.matcher(body);
                    while (bodyMatcher.find()) {
                        String paramName = bodyMatcher.group(1).trim();
                        String paramValue = bodyMatcher.group(2).trim();
                        
                        String key = paramName + "=" + paramValue;
                        paramUsages.computeIfAbsent(key, k -> new ArrayList<>()).add(i);
                    }
                }
            }
        }
        
        for (Map.Entry<String, List<Integer>> entry : paramUsages.entrySet()) {
            if (entry.getValue().size() > 1) {
                result.addParameterDependency(entry.getKey(), entry.getValue());
            }
        }
    }
    
    private void analyzeSequencePatterns(List<IHttpRequestResponse> messages, ChainAnalysisResult result) {
        if (messages.size() < 2) {
            return;
        }
        
        // 分析登录 -> 操作 -> 登出的模式
        analyzeLoginLogoutSequence(messages, result);
        
        // 分析 CRUD 操作序列
        analyzeCRUDSequence(messages, result);
    }
    
    private void analyzeLoginLogoutSequence(List<IHttpRequestResponse> messages, ChainAnalysisResult result) {
        int loginIndex = -1;
        int logoutIndex = -1;
        
        for (int i = 0; i < messages.size(); i++) {
            IHttpRequestResponse message = messages.get(i);
            if (message.getRequest() == null) continue;
            
            String request = new String(message.getRequest()).toLowerCase();
            
            if (request.contains("login") || request.contains("signin") || request.contains("auth")) {
                if (loginIndex == -1) loginIndex = i;
            }
            
            if (request.contains("logout") || request.contains("signout")) {
                logoutIndex = i;
            }
        }
        
        if (loginIndex >= 0 && logoutIndex > loginIndex) {
            result.addSequence("login-logout", loginIndex, logoutIndex);
        }
    }
    
    private void analyzeCRUDSequence(List<IHttpRequestResponse> messages, ChainAnalysisResult result) {
        List<Integer> createIndexes = new ArrayList<>();
        List<Integer> readIndexes = new ArrayList<>();
        List<Integer> updateIndexes = new ArrayList<>();
        List<Integer> deleteIndexes = new ArrayList<>();
        
        for (int i = 0; i < messages.size(); i++) {
            IHttpRequestResponse message = messages.get(i);
            if (message.getRequest() == null) continue;
            
            String request = new String(message.getRequest());
            String method = extractMethod(request);
            String url = extractUrl(request).toLowerCase();
            
            if (method == null) continue;
            
            // POST -> 创建
            if (method.equals("POST") && (url.contains("create") || url.contains("add") || url.contains("new"))) {
                createIndexes.add(i);
            }
            // GET -> 读取
            else if (method.equals("GET") && (url.contains("get") || url.contains("view") || url.contains("detail"))) {
                readIndexes.add(i);
            }
            // PUT/PATCH -> 更新
            else if ((method.equals("PUT") || method.equals("PATCH")) && 
                     (url.contains("update") || url.contains("edit") || url.contains("modify"))) {
                updateIndexes.add(i);
            }
            // DELETE -> 删除
            else if (method.equals("DELETE") && (url.contains("delete") || url.contains("remove"))) {
                deleteIndexes.add(i);
            }
        }
        
        if (!createIndexes.isEmpty() || !readIndexes.isEmpty() || 
            !updateIndexes.isEmpty() || !deleteIndexes.isEmpty()) {
            result.addCRUDSequence(createIndexes, readIndexes, updateIndexes, deleteIndexes);
        }
    }
    
    private String extractMethod(String request) {
        int spaceIndex = request.indexOf(' ');
        if (spaceIndex > 0) {
            return request.substring(0, spaceIndex).toUpperCase();
        }
        return null;
    }
    
    private String extractUrl(String request) {
        Pattern urlPattern = Pattern.compile("^[A-Z]+\\s+([^\\s]+)");
        Matcher matcher = urlPattern.matcher(request);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }
    
    public static class ChainAnalysisResult {
        private Map<String, List<Integer>> sessionDependencies = new LinkedHashMap<>();
        private Map<String, SessionValue> sessionValues = new LinkedHashMap<>();
        private Map<String, List<Integer>> tokenDependencies = new LinkedHashMap<>();
        private Map<String, List<Integer>> parameterDependencies = new LinkedHashMap<>();
        private Map<String, int[]> sequences = new LinkedHashMap<>();
        private CRUDSequence crudSequence;
        
        public void addSessionDependency(String cookieName, List<Integer> requestIndexes) {
            sessionDependencies.put(cookieName, requestIndexes);
        }
        
        public void addSessionValue(String name, String value, int requestIndex) {
            sessionValues.put(name + "_" + requestIndex, new SessionValue(name, value, requestIndex));
        }
        
        public void addTokenDependency(String token, List<Integer> requestIndexes) {
            tokenDependencies.put(token, requestIndexes);
        }
        
        public void addParameterDependency(String param, List<Integer> requestIndexes) {
            parameterDependencies.put(param, requestIndexes);
        }
        
        public void addSequence(String name, int startIndex, int endIndex) {
            sequences.put(name, new int[]{startIndex, endIndex});
        }
        
        public void addCRUDSequence(List<Integer> create, List<Integer> read, 
                                    List<Integer> update, List<Integer> delete) {
            this.crudSequence = new CRUDSequence(create, read, update, delete);
        }
        
        public boolean hasSessionDependency() {
            return !sessionDependencies.isEmpty();
        }
        
        public boolean hasTokenDependency() {
            return !tokenDependencies.isEmpty();
        }
        
        public boolean hasParameterDependency() {
            return !parameterDependencies.isEmpty();
        }
        
        public boolean hasSequenceDependency() {
            return !sequences.isEmpty();
        }
        
        public Map<String, List<Integer>> getSessionDependencies() {
            return new LinkedHashMap<>(sessionDependencies);
        }
        
        public Map<String, List<Integer>> getTokenDependencies() {
            return new LinkedHashMap<>(tokenDependencies);
        }
        
        public Map<String, List<Integer>> getParameterDependencies() {
            return new LinkedHashMap<>(parameterDependencies);
        }
        
        public Map<String, int[]> getSequences() {
            return new LinkedHashMap<>(sequences);
        }
        
        public CRUDSequence getCRUDSequence() {
            return crudSequence;
        }
    }
    
    public static class SessionValue {
        private String name;
        private String value;
        private int requestIndex;
        
        public SessionValue(String name, String value, int requestIndex) {
            this.name = name;
            this.value = value;
            this.requestIndex = requestIndex;
        }
        
        public String getName() { return name; }
        public String getValue() { return value; }
        public int getRequestIndex() { return requestIndex; }
    }
    
    public static class CRUDSequence {
        private List<Integer> createIndexes;
        private List<Integer> readIndexes;
        private List<Integer> updateIndexes;
        private List<Integer> deleteIndexes;
        
        public CRUDSequence(List<Integer> create, List<Integer> read, 
                           List<Integer> update, List<Integer> delete) {
            this.createIndexes = create != null ? new ArrayList<>(create) : new ArrayList<>();
            this.readIndexes = read != null ? new ArrayList<>(read) : new ArrayList<>();
            this.updateIndexes = update != null ? new ArrayList<>(update) : new ArrayList<>();
            this.deleteIndexes = delete != null ? new ArrayList<>(delete) : new ArrayList<>();
        }
        
        public List<Integer> getCreateIndexes() { return new ArrayList<>(createIndexes); }
        public List<Integer> getReadIndexes() { return new ArrayList<>(readIndexes); }
        public List<Integer> getUpdateIndexes() { return new ArrayList<>(updateIndexes); }
        public List<Integer> getDeleteIndexes() { return new ArrayList<>(deleteIndexes); }
    }
}
