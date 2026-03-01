package burp.waf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;

public class WAFProbeDetector {
    
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final WAFDetector passiveDetector;
    private final Map<String, WAFSignature> extendedSignatures;
    private final List<ProbePayload> probePayloads;
    private final ExecutorService executorService;
    
    private static final int PROBE_TIMEOUT_MS = 10000;
    private static final int MAX_CONCURRENT_PROBES = 3;
    
    public WAFProbeDetector(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.passiveDetector = new WAFDetector();
        this.extendedSignatures = new ConcurrentHashMap<>();
        this.probePayloads = new ArrayList<>();
        this.executorService = Executors.newFixedThreadPool(MAX_CONCURRENT_PROBES);
        
        initializeExtendedSignatures();
        initializeProbePayloads();
    }
    
    private void initializeExtendedSignatures() {
        addCloudWAFSignatures();
        addHardwareWAFSignatures();
        addSoftwareWAFSignatures();
        addCDNWAFSignatures();
    }
    
    private void addCloudWAFSignatures() {
        WAFSignature cloudflare = new WAFSignature("cloudflare", "Cloudflare");
        cloudflare.setVendor("Cloudflare");
        cloudflare.setType(WAFSignature.WAFType.CLOUD);
        cloudflare.addBypassTechnique("chunked_encoding");
        cloudflare.addBypassTechnique("case_variation");
        cloudflare.addBypassTechnique("unicode_normalization");
        cloudflare.addBypassTechnique("http2_smuggling");
        cloudflare.setConfidence(95);
        addExtendedRule(cloudflare, "cf-ray", "cf-ray", 35);
        addExtendedRule(cloudflare, "cf-cache-status", "cf-cache-status", 20);
        addExtendedRule(cloudflare, "block-page", "cloudflare|cf-browser-verification|cf_clearance|attention required|checking your browser", 30);
        addExtendedRule(cloudflare, "403-block", "error 403|access denied|ray id:", 25, 403);
        extendedSignatures.put(cloudflare.getId(), cloudflare);
        
        WAFSignature awswaf = new WAFSignature("awswaf", "AWS WAF");
        awswaf.setVendor("Amazon");
        awswaf.setType(WAFSignature.WAFType.CLOUD);
        awswaf.addBypassTechnique("chunked_encoding");
        awswaf.addBypassTechnique("http_version");
        awswaf.addBypassTechnique("encoding_variation");
        awswaf.setConfidence(90);
        addExtendedRule(awswaf, "x-amz-cf", "x-amz-cf|x-amzn-requestid|aws-waf", 30);
        addExtendedRule(awswaf, "block-page", "request blocked|access denied.*aws|x-amz-cf-id", 25);
        extendedSignatures.put(awswaf.getId(), awswaf);
        
        WAFSignature akamai = new WAFSignature("akamai", "Akamai Kona");
        akamai.setVendor("Akamai");
        akamai.setType(WAFSignature.WAFType.CLOUD);
        akamai.addBypassTechnique("chunked_encoding");
        akamai.addBypassTechnique("encoding_variation");
        akamai.setConfidence(90);
        addExtendedRule(akamai, "akamai-header", "akamai|x-akamai|akamai-origin-hop", 30);
        addExtendedRule(akamai, "block-page", "access denied|request rejected|akamai", 25);
        extendedSignatures.put(akamai.getId(), akamai);
        
        WAFSignature imperva = new WAFSignature("imperva", "Imperva Cloud WAF");
        imperva.setVendor("Imperva");
        imperva.setType(WAFSignature.WAFType.CLOUD);
        imperva.addBypassTechnique("chunked_encoding");
        imperva.addBypassTechnique("encoding_chain");
        imperva.setConfidence(90);
        addExtendedRule(imperva, "incap-cookie", "incap_ses_|visid_incap_|incap_ses", 35);
        addExtendedRule(imperva, "block-page", "incapsula|imperva|request denied", 30);
        extendedSignatures.put(imperva.getId(), imperva);
        
        WAFSignature azure = new WAFSignature("azure", "Azure WAF");
        azure.setVendor("Microsoft");
        azure.setType(WAFSignature.WAFType.CLOUD);
        azure.addBypassTechnique("encoding_variation");
        azure.addBypassTechnique("case_variation");
        azure.setConfidence(85);
        addExtendedRule(azure, "azure-header", "x-azure|x-ms-|azure", 25);
        addExtendedRule(azure, "block-page", "azure|front door|application gateway", 25);
        extendedSignatures.put(azure.getId(), azure);
        
        WAFSignature f5cloud = new WAFSignature("f5cloud", "F5 Cloud WAF");
        f5cloud.setVendor("F5 Networks");
        f5cloud.setType(WAFSignature.WAFType.CLOUD);
        f5cloud.addBypassTechnique("encoding_chain");
        f5cloud.addBypassTechnique("case_variation");
        f5cloud.setConfidence(85);
        addExtendedRule(f5cloud, "f5-header", "x-f5|f5-bigip", 30);
        extendedSignatures.put(f5cloud.getId(), f5cloud);
    }
    
    private void addHardwareWAFSignatures() {
        WAFSignature nsfocus = new WAFSignature("nsfocus", "NSFOCUS WAF");
        nsfocus.setVendor("NSFOCUS");
        nsfocus.setType(WAFSignature.WAFType.HARDWARE);
        nsfocus.addBypassTechnique("encoding_chain");
        nsfocus.addBypassTechnique("case_variation");
        nsfocus.addBypassTechnique("comment_injection");
        nsfocus.setConfidence(90);
        addExtendedRule(nsfocus, "nsfocus-header", "nsfocus|nsfocuswaf", 35);
        addExtendedRule(nsfocus, "block-page", "nsfocus|WAF", 30);
        extendedSignatures.put(nsfocus.getId(), nsfocus);
        
        WAFSignature venustech = new WAFSignature("venustech", "Venusense WAF");
        venustech.setVendor("Venustech");
        venustech.setType(WAFSignature.WAFType.HARDWARE);
        venustech.addBypassTechnique("encoding_chain");
        venustech.addBypassTechnique("null_byte");
        venustech.setConfidence(90);
        addExtendedRule(venustech, "venus-header", "venustech|", 35);
        addExtendedRule(venustech, "block-page", "venustech|", 30);
        extendedSignatures.put(venustech.getId(), venustech);
        
        WAFSignature dbappsecurity = new WAFSignature("dbappsecurity", "DBAppSecurity WAF");
        dbappsecurity.setVendor("DBAppSecurity");
        dbappsecurity.setType(WAFSignature.WAFType.HARDWARE);
        dbappsecurity.addBypassTechnique("encoding_chain");
        dbappsecurity.addBypassTechnique("multipart_boundary");
        dbappsecurity.setConfidence(90);
        addExtendedRule(dbappsecurity, "dh-body", "dbappsecurity|WAF", 35);
        extendedSignatures.put(dbappsecurity.getId(), dbappsecurity);
        
        WAFSignature topsec = new WAFSignature("topsec", "Topsec WAF");
        topsec.setVendor("Topsec");
        topsec.setType(WAFSignature.WAFType.HARDWARE);
        topsec.addBypassTechnique("encoding_chain");
        topsec.addBypassTechnique("double_url_encode");
        topsec.setConfidence(85);
        addExtendedRule(topsec, "topsec-header", "topsec|", 35);
        extendedSignatures.put(topsec.getId(), topsec);
        
        WAFSignature hillstone = new WAFSignature("hillstone", "Hillstone WAF");
        hillstone.setVendor("Hillstone");
        hillstone.setType(WAFSignature.WAFType.HARDWARE);
        hillstone.addBypassTechnique("case_variation");
        hillstone.setConfidence(85);
        addExtendedRule(hillstone, "hillstone-header", "hillstone|hillstone-waf", 35);
        extendedSignatures.put(hillstone.getId(), hillstone);
        
        WAFSignature sangfor = new WAFSignature("sangfor", "Sangfor WAF");
        sangfor.setVendor("Sangfor");
        sangfor.setType(WAFSignature.WAFType.HARDWARE);
        sangfor.addBypassTechnique("unicode_encode");
        sangfor.addBypassTechnique("double_url_encode");
        sangfor.setConfidence(85);
        addExtendedRule(sangfor, "sangfor-header", "sangfor|sangfor-waf", 35);
        extendedSignatures.put(sangfor.getId(), sangfor);
    }
    
    private void addSoftwareWAFSignatures() {
        WAFSignature modsec = new WAFSignature("modsecurity", "ModSecurity");
        modsec.setVendor("OWASP");
        modsec.setType(WAFSignature.WAFType.SOFTWARE);
        modsec.addBypassTechnique("comment_injection");
        modsec.addBypassTechnique("encoding_chain");
        modsec.addBypassTechnique("null_byte");
        modsec.addBypassTechnique("case_variation");
        modsec.setConfidence(95);
        addExtendedRule(modsec, "modsec-header", "mod_security|modsecurity", 35);
        addExtendedRule(modsec, "block-page", "mod_security|modsecurity|Not Acceptable|internal server error", 30);
        extendedSignatures.put(modsec.getId(), modsec);
        
        WAFSignature safedog = new WAFSignature("safedog", "SafeDog WAF");
        safedog.setVendor("SafeDog");
        safedog.setType(WAFSignature.WAFType.SOFTWARE);
        safedog.addBypassTechnique("double_url_encode");
        safedog.addBypassTechnique("unicode_encode");
        safedog.addBypassTechnique("h_w_event_attack");
        safedog.setConfidence(95);
        addExtendedRule(safedog, "safedog-header", "safedog|safedogwaf", 35);
        addExtendedRule(safedog, "block-page", "safedog|", 30);
        extendedSignatures.put(safedog.getId(), safedog);
        
        WAFSignature yunsuo = new WAFSignature("yunsuo", "Yunsuo WAF");
        yunsuo.setVendor("Yunsuo");
        yunsuo.setType(WAFSignature.WAFType.SOFTWARE);
        yunsuo.addBypassTechnique("chunked_encoding");
        yunsuo.addBypassTechnique("multipart_boundary");
        yunsuo.addBypassTechnique("url_encode");
        yunsuo.setConfidence(95);
        addExtendedRule(yunsuo, "yunsuo-header", "yunsuo|yunsuo_session", 35);
        addExtendedRule(yunsuo, "block-page", "yunsuo|", 30);
        extendedSignatures.put(yunsuo.getId(), yunsuo);
        
        WAFSignature naxsi = new WAFSignature("naxsi", "Naxsi");
        naxsi.setVendor("Naxsi");
        naxsi.setType(WAFSignature.WAFType.SOFTWARE);
        naxsi.addBypassTechnique("case_variation");
        naxsi.addBypassTechnique("encoding_variation");
        naxsi.setConfidence(90);
        addExtendedRule(naxsi, "naxsi-body", "naxsi|blocked by naxsi|request denied", 35);
        extendedSignatures.put(naxsi.getId(), naxsi);
        
        WAFSignature ngxsys = new WAFSignature("ngxsys", "ngx_waf");
        ngxsys.setVendor("ngx_waf");
        ngxsys.setType(WAFSignature.WAFType.SOFTWARE);
        ngxsys.addBypassTechnique("case_variation");
        ngxsys.setConfidence(80);
        addExtendedRule(ngxsys, "ngxsys-body", "ngx.waf|blocked", 30);
        extendedSignatures.put(ngxsys.getId(), ngxsys);
        
        WAFSignature baidu = new WAFSignature("baidu", "Baidu WAF");
        baidu.setVendor("Baidu");
        baidu.setType(WAFSignature.WAFType.CLOUD);
        baidu.addBypassTechnique("encoding_chain");
        baidu.setConfidence(85);
        addExtendedRule(baidu, "baidu-header", "baidu|bce", 25);
        addExtendedRule(baidu, "block-page", "baidu|bce", 25);
        extendedSignatures.put(baidu.getId(), baidu);
        
        WAFSignature aliyun = new WAFSignature("aliyun", "Aliyun WAF");
        aliyun.setVendor("Alibaba");
        aliyun.setType(WAFSignature.WAFType.CLOUD);
        aliyun.addBypassTechnique("chunked_encoding");
        aliyun.addBypassTechnique("unicode_normalize");
        aliyun.setConfidence(90);
        addExtendedRule(aliyun, "aliyun-header", "aliyun|alibaba|alicdn", 30);
        addExtendedRule(aliyun, "block-page", "aliyun|alibaba|error.*request", 25);
        extendedSignatures.put(aliyun.getId(), aliyun);
        
        WAFSignature tencent = new WAFSignature("tencent", "Tencent Cloud WAF");
        tencent.setVendor("Tencent");
        tencent.setType(WAFSignature.WAFType.CLOUD);
        tencent.addBypassTechnique("encoding_chain");
        tencent.addBypassTechnique("case_variation");
        tencent.setConfidence(90);
        addExtendedRule(tencent, "tencent-header", "tencent|qcloud|腾讯", 30);
        addExtendedRule(tencent, "block-page", "tencent|qcloud", 25);
        extendedSignatures.put(tencent.getId(), tencent);
        
        WAFSignature huawei = new WAFSignature("huawei", "Huawei Cloud WAF");
        huawei.setVendor("Huawei");
        huawei.setType(WAFSignature.WAFType.CLOUD);
        huawei.addBypassTechnique("encoding_chain");
        huawei.setConfidence(85);
        addExtendedRule(huawei, "huawei-header", "huawei|hwclouds", 30);
        extendedSignatures.put(huawei.getId(), huawei);
    }
    
    private void addCDNWAFSignatures() {
        WAFSignature cloudfront = new WAFSignature("cloudfront", "CloudFront");
        cloudfront.setVendor("Amazon");
        cloudfront.setType(WAFSignature.WAFType.CDN);
        cloudfront.addBypassTechnique("encoding_variation");
        cloudfront.setConfidence(85);
        addExtendedRule(cloudfront, "cf-header", "x-amz-cf|x-cache|cloudfront", 30);
        addExtendedRule(cloudfront, "block-page", "cloudfront|access denied", 25);
        extendedSignatures.put(cloudfront.getId(), cloudfront);
        
        WAFSignature fastly = new WAFSignature("fastly", "Fastly WAF");
        fastly.setVendor("Fastly");
        fastly.setType(WAFSignature.WAFType.CDN);
        fastly.addBypassTechnique("encoding_variation");
        fastly.setConfidence(80);
        addExtendedRule(fastly, "fastly-header", "fastly|x-served-by|x-cache", 30);
        extendedSignatures.put(fastly.getId(), fastly);
        
        WAFSignature cloudcdn = new WAFSignature("cloudcdn", "Cloud CDN");
        cloudcdn.setVendor("Google");
        cloudcdn.setType(WAFSignature.WAFType.CDN);
        cloudcdn.addBypassTechnique("case_variation");
        cloudcdn.setConfidence(80);
        addExtendedRule(cloudcdn, "gcp-header", "x-goog|google|gstatic", 25);
        extendedSignatures.put(cloudcdn.getId(), cloudcdn);
        
        WAFSignature cdn77 = new WAFSignature("cdn77", "CDN77 WAF");
        cdn77.setVendor("CDN77");
        cdn77.setType(WAFSignature.WAFType.CDN);
        cdn77.addBypassTechnique("encoding_variation");
        cdn77.setConfidence(75);
        addExtendedRule(cdn77, "cdn77-header", "cdn77|x-cdn", 25);
        extendedSignatures.put(cdn77.getId(), cdn77);
        
        WAFSignature stackpath = new WAFSignature("stackpath", "StackPath WAF");
        stackpath.setVendor("StackPath");
        stackpath.setType(WAFSignature.WAFType.CDN);
        stackpath.addBypassTechnique("encoding_chain");
        stackpath.setConfidence(80);
        addExtendedRule(stackpath, "sp-header", "stackpath|x-sp", 30);
        extendedSignatures.put(stackpath.getId(), stackpath);
        
        WAFSignature sucuri = new WAFSignature("sucuri", "Sucuri WAF");
        sucuri.setVendor("Sucuri");
        sucuri.setType(WAFSignature.WAFType.CDN);
        sucuri.addBypassTechnique("case_variation");
        sucuri.addBypassTechnique("encoding_variation");
        sucuri.setConfidence(85);
        addExtendedRule(sucuri, "sucuri-header", "sucuri|x-sucuri", 35);
        addExtendedRule(sucuri, "block-page", "sucuri|access denied", 30);
        extendedSignatures.put(sucuri.getId(), sucuri);
    }
    
    private void addExtendedRule(WAFSignature sig, String ruleName, String pattern, int weight) {
        addExtendedRule(sig, ruleName, pattern, weight, null);
    }
    
    private void addExtendedRule(WAFSignature sig, String ruleName, String pattern, int weight, Integer statusCode) {
        WAFSignature.SignatureRule rule = new WAFSignature.SignatureRule(ruleName, ruleName);
        if (pattern.contains("|") && (pattern.toLowerCase().contains("header") || ruleName.contains("header"))) {
            rule.setHeaderPattern(pattern);
        } else if (pattern.contains("|")) {
            rule.setBodyPattern(pattern);
        } else {
            rule.setHeaderPattern(pattern);
            rule.setBodyPattern(pattern);
        }
        rule.setWeight(weight);
        if (statusCode != null) {
            rule.setStatusCode(statusCode);
        }
        sig.addRule(rule);
    }
    
    private void initializeProbePayloads() {
        addSQLInjectionProbes();
        addXSSProbes();
        addPathTraversalProbes();
        addCommandInjectionProbes();
        addGenericProbes();
    }
    
    private void addSQLInjectionProbes() {
        probePayloads.add(new ProbePayload("sqli_single_quote", "SQL Injection - Single Quote", 
            "' OR '1'='1", ProbePayload.ProbeType.SQLI));
        probePayloads.add(new ProbePayload("sqli_union", "SQL Injection - UNION", 
            "' UNION SELECT NULL--", ProbePayload.ProbeType.SQLI));
        probePayloads.add(new ProbePayload("sqli_comment", "SQL Injection - Comment", 
            "1/**/OR/**/1=1", ProbePayload.ProbeType.SQLI));
        probePayloads.add(new ProbePayload("sqli_sleep", "SQL Injection - Time Based", 
            "'; WAITFOR DELAY '0:0:5'--", ProbePayload.ProbeType.SQLI));
        probePayloads.add(new ProbePayload("sqli_mysql", "SQL Injection - MySQL", 
            "' AND SLEEP(5)--", ProbePayload.ProbeType.SQLI));
    }
    
    private void addXSSProbes() {
        probePayloads.add(new ProbePayload("xss_script", "XSS - Script Tag", 
            "<script>alert('XSS')</script>", ProbePayload.ProbeType.XSS));
        probePayloads.add(new ProbePayload("xss_img", "XSS - Image Tag", 
            "<img src=x onerror=alert('XSS')>", ProbePayload.ProbeType.XSS));
        probePayloads.add(new ProbePayload("xss_svg", "XSS - SVG Tag", 
            "<svg onload=alert('XSS')>", ProbePayload.ProbeType.XSS));
        probePayloads.add(new ProbePayload("xss_event", "XSS - Event Handler", 
            "\"onfocus=alert('XSS') autofocus=\"", ProbePayload.ProbeType.XSS));
        probePayloads.add(new ProbePayload("xss_javascript", "XSS - JavaScript Protocol", 
            "javascript:alert('XSS')", ProbePayload.ProbeType.XSS));
    }
    
    private void addPathTraversalProbes() {
        probePayloads.add(new ProbePayload("traversal_basic", "Path Traversal - Basic", 
            "../../../etc/passwd", ProbePayload.ProbeType.PATH_TRAVERSAL));
        probePayloads.add(new ProbePayload("traversal_encoded", "Path Traversal - Encoded", 
            "..%2f..%2f..%2fetc/passwd", ProbePayload.ProbeType.PATH_TRAVERSAL));
        probePayloads.add(new ProbePayload("traversal_double", "Path Traversal - Double Encoded", 
            "..%252f..%252f..%252fetc/passwd", ProbePayload.ProbeType.PATH_TRAVERSAL));
        probePayloads.add(new ProbePayload("traversal_null", "Path Traversal - Null Byte", 
            "../../../etc/passwd%00.jpg", ProbePayload.ProbeType.PATH_TRAVERSAL));
    }
    
    private void addCommandInjectionProbes() {
        probePayloads.add(new ProbePayload("cmd_pipe", "Command Injection - Pipe", 
            "| cat /etc/passwd", ProbePayload.ProbeType.CMDI));
        probePayloads.add(new ProbePayload("cmd_semicolon", "Command Injection - Semicolon", 
            "; cat /etc/passwd", ProbePayload.ProbeType.CMDI));
        probePayloads.add(new ProbePayload("cmd_backtick", "Command Injection - Backtick", 
            "`cat /etc/passwd`", ProbePayload.ProbeType.CMDI));
        probePayloads.add(new ProbePayload("cmd_and", "Command Injection - AND", 
            "&& cat /etc/passwd", ProbePayload.ProbeType.CMDI));
        probePayloads.add(new ProbePayload("cmd_or", "Command Injection - OR", 
            "|| cat /etc/passwd", ProbePayload.ProbeType.CMDI));
    }
    
    private void addGenericProbes() {
        probePayloads.add(new ProbePayload("generic_scan", "Scanner Detection", 
            "Nessus|Nikto|SQLMap|Acunetix", ProbePayload.ProbeType.GENERIC));
        probePayloads.add(new ProbePayload("generic_bypass", "Bypass Attempt", 
            "eval(base64_decode", ProbePayload.ProbeType.GENERIC));
    }
    
    public ProbeDetectionResult performActiveProbe(IHttpRequestResponse baseMessage, String parameter) {
        ProbeDetectionResult result = new ProbeDetectionResult();
        
        try {
            WAFSignature.DetectionResult passiveResult = passiveDetect(baseMessage);
            if (passiveResult.isDetected()) {
                result.setPassiveDetection(passiveResult);
                result.setDetectedWAF(passiveResult.getWafName());
                result.setConfidence(passiveResult.getScore());
            }
            
            List<ProbeResult> probeResults = sendProbes(baseMessage, parameter);
            result.setProbeResults(probeResults);
            
            analyzeProbeResults(result, probeResults);
            
        } catch (Exception e) {
            result.setError(e.getMessage());
            callbacks.printError("[WAFProbeDetector] Probe error: " + e.getMessage());
        }
        
        return result;
    }
    
    private WAFSignature.DetectionResult passiveDetect(IHttpRequestResponse message) {
        if (message.getResponse() == null) {
            return new WAFSignature.DetectionResult(false, "Unknown", "Unknown", 
                WAFSignature.WAFType.UNKNOWN, 0, new ArrayList<>());
        }
        
        String responseStr = new String(message.getResponse(), StandardCharsets.UTF_8);
        
        Map<String, String> headers = extractHeaders(responseStr);
        String body = extractBody(responseStr);
        int statusCode = extractStatusCode(responseStr);
        
        for (WAFSignature sig : extendedSignatures.values()) {
            WAFSignature.DetectionResult result = sig.detect(headers, body, statusCode);
            if (result.isDetected()) {
                return result;
            }
        }
        
        return passiveDetector.detectPrimary(headers, body, statusCode);
    }
    
    private List<ProbeResult> sendProbes(IHttpRequestResponse baseMessage, String parameter) {
        List<ProbeResult> results = new ArrayList<>();
        List<Future<ProbeResult>> futures = new ArrayList<>();
        
        for (ProbePayload payload : probePayloads) {
            Future<ProbeResult> future = executorService.submit(() -> 
                sendSingleProbe(baseMessage, parameter, payload));
            futures.add(future);
        }
        
        for (Future<ProbeResult> future : futures) {
            try {
                ProbeResult result = future.get(PROBE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                if (result != null) {
                    results.add(result);
                }
            } catch (TimeoutException | InterruptedException | ExecutionException e) {
                callbacks.printError("[WAFProbeDetector] Probe timeout or error: " + e.getMessage());
            }
        }
        
        return results;
    }
    
    private ProbeResult sendSingleProbe(IHttpRequestResponse baseMessage, String parameter, ProbePayload payload) {
        try {
            byte[] baseRequest = baseMessage.getRequest();
            String requestStr = new String(baseRequest, StandardCharsets.UTF_8);
            
            String modifiedRequest;
            if (parameter != null && !parameter.isEmpty()) {
                modifiedRequest = injectPayload(requestStr, parameter, payload.getPayload());
            } else {
                modifiedRequest = appendProbeToQuery(requestStr, payload.getPayload());
            }
            
            byte[] requestBytes = modifiedRequest.getBytes(StandardCharsets.UTF_8);
            
            IHttpService httpService = baseMessage.getHttpService();
            
            IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, requestBytes);
            
            if (response != null && response.getResponse() != null) {
                String responseStr = new String(response.getResponse(), StandardCharsets.UTF_8);
                int statusCode = extractStatusCode(responseStr);
                String responseBody = extractBody(responseStr);
                
                boolean blocked = isBlocked(statusCode, responseBody);
                String detectedBy = detectBlockingWAF(responseStr);
                
                return new ProbeResult(payload, statusCode, blocked, detectedBy, responseBody);
            }
            
        } catch (Exception e) {
            callbacks.printError("[WAFProbeDetector] Single probe error: " + e.getMessage());
        }
        
        return null;
    }
    
    private String injectPayload(String request, String parameter, String payload) {
        String encodedPayload = payload;
        
        Pattern paramPattern = Pattern.compile("(" + Pattern.quote(parameter) + "=)([^&\\s]*)");
        Matcher matcher = paramPattern.matcher(request);
        
        if (matcher.find()) {
            return matcher.replaceFirst("$1" + encodedPayload);
        }
        
        return appendProbeToQuery(request, payload);
    }
    
    private String appendProbeToQuery(String request, String payload) {
        Pattern queryPattern = Pattern.compile("(\\?[^\s]*)");
        Matcher matcher = queryPattern.matcher(request);
        
        if (matcher.find()) {
            String query = matcher.group(1);
            String separator = query.contains("?") && !query.endsWith("?") ? "&" : "";
            return request.replace(query, query + separator + "probe=" + payload);
        }
        
        Pattern pathPattern = Pattern.compile("^([A-Z]+\\s+[^\\s]+)");
        Matcher pathMatcher = pathPattern.matcher(request);
        if (pathMatcher.find()) {
            String path = pathMatcher.group(1);
            return request.replace(path, path + "?probe=" + payload);
        }
        
        return request;
    }
    
    private boolean isBlocked(int statusCode, String responseBody) {
        if (statusCode == 403 || statusCode == 406 || statusCode == 429) {
            return true;
        }
        
        if (responseBody != null) {
            String lowerBody = responseBody.toLowerCase();
            String[] blockKeywords = {
                "blocked", "denied", "forbidden", "rejected", 
                "waf", "firewall", "security", "attack",
                "unauthorized", "not allowed", "access denied"
            };
            
            for (String keyword : blockKeywords) {
                if (lowerBody.contains(keyword)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private String detectBlockingWAF(String response) {
        String lowerResponse = response.toLowerCase();
        
        for (Map.Entry<String, WAFSignature> entry : extendedSignatures.entrySet()) {
            WAFSignature sig = entry.getValue();
            for (WAFSignature.SignatureRule rule : sig.getRules()) {
                if (rule.getBodyPattern() != null) {
                    Pattern pattern = Pattern.compile(rule.getBodyPattern(), Pattern.CASE_INSENSITIVE);
                    if (pattern.matcher(lowerResponse).find()) {
                        return sig.getName();
                    }
                }
            }
        }
        
        return "Unknown WAF";
    }
    
    private void analyzeProbeResults(ProbeDetectionResult result, List<ProbeResult> probeResults) {
        Map<String, Integer> wafCounts = new HashMap<>();
        int blockedCount = 0;
        
        for (ProbeResult probe : probeResults) {
            if (probe.isBlocked()) {
                blockedCount++;
                String waf = probe.getDetectedWAF();
                if (waf != null && !"Unknown WAF".equals(waf)) {
                    wafCounts.merge(waf, 1, Integer::sum);
                }
            }
        }
        
        if (blockedCount > 0) {
            result.setWafDetected(true);
            
            Map.Entry<String, Integer> maxEntry = null;
            for (Map.Entry<String, Integer> entry : wafCounts.entrySet()) {
                if (maxEntry == null || entry.getValue() > maxEntry.getValue()) {
                    maxEntry = entry;
                }
            }
            
            if (maxEntry != null) {
                result.setDetectedWAF(maxEntry.getKey());
                result.setConfidence(Math.min(100, 50 + maxEntry.getValue() * 10));
            } else {
                result.setDetectedWAF("Unknown WAF");
                result.setConfidence(50);
            }
        }
        
        result.setBlockRate(probeResults.isEmpty() ? 0 : (double) blockedCount / probeResults.size());
    }
    
    private Map<String, String> extractHeaders(String response) {
        Map<String, String> headers = new LinkedHashMap<>();
        
        int headerEnd = response.indexOf("\r\n\r\n");
        if (headerEnd < 0) {
            return headers;
        }
        
        String headerSection = response.substring(0, headerEnd);
        String[] lines = headerSection.split("\r\n");
        
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                String name = line.substring(0, colonIndex).trim();
                String value = line.substring(colonIndex + 1).trim();
                headers.put(name, value);
            }
        }
        
        return headers;
    }
    
    private String extractBody(String response) {
        int bodyStart = response.indexOf("\r\n\r\n");
        if (bodyStart > 0 && bodyStart + 4 < response.length()) {
            return response.substring(bodyStart + 4);
        }
        return "";
    }
    
    private int extractStatusCode(String response) {
        Pattern statusPattern = Pattern.compile("HTTP/\\d\\.\\d\\s+(\\d+)");
        Matcher matcher = statusPattern.matcher(response);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return 0;
    }
    
    public List<WAFSignature> getAllExtendedSignatures() {
        return new ArrayList<>(extendedSignatures.values());
    }
    
    public List<ProbePayload> getProbePayloads() {
        return new ArrayList<>(probePayloads);
    }
    
    public void shutdown() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }
    }
    
    public static class ProbePayload {
        public enum ProbeType {
            SQLI, XSS, PATH_TRAVERSAL, CMDI, GENERIC
        }
        
        private final String id;
        private final String name;
        private final String payload;
        private final ProbeType type;
        
        public ProbePayload(String id, String name, String payload, ProbeType type) {
            this.id = id;
            this.name = name;
            this.payload = payload;
            this.type = type;
        }
        
        public String getId() { return id; }
        public String getName() { return name; }
        public String getPayload() { return payload; }
        public ProbeType getType() { return type; }
    }
    
    public static class ProbeResult {
        private final ProbePayload probePayload;
        private final int statusCode;
        private final boolean blocked;
        private final String detectedWAF;
        private final String responseBody;
        
        public ProbeResult(ProbePayload probePayload, int statusCode, boolean blocked, 
                          String detectedWAF, String responseBody) {
            this.probePayload = probePayload;
            this.statusCode = statusCode;
            this.blocked = blocked;
            this.detectedWAF = detectedWAF;
            this.responseBody = responseBody != null && responseBody.length() > 500 
                ? responseBody.substring(0, 500) : responseBody;
        }
        
        public ProbePayload getProbePayload() { return probePayload; }
        public int getStatusCode() { return statusCode; }
        public boolean isBlocked() { return blocked; }
        public String getDetectedWAF() { return detectedWAF; }
        public String getResponseBody() { return responseBody; }
    }
    
    public static class ProbeDetectionResult {
        private boolean wafDetected = false;
        private String detectedWAF = "Unknown";
        private int confidence = 0;
        private double blockRate = 0;
        private WAFSignature.DetectionResult passiveDetection;
        private List<ProbeResult> probeResults = new ArrayList<>();
        private String error;
        
        public boolean isWafDetected() { return wafDetected; }
        public void setWafDetected(boolean wafDetected) { this.wafDetected = wafDetected; }
        
        public String getDetectedWAF() { return detectedWAF; }
        public void setDetectedWAF(String detectedWAF) { this.detectedWAF = detectedWAF; }
        
        public int getConfidence() { return confidence; }
        public void setConfidence(int confidence) { this.confidence = Math.max(0, Math.min(100, confidence)); }
        
        public double getBlockRate() { return blockRate; }
        public void setBlockRate(double blockRate) { this.blockRate = blockRate; }
        
        public WAFSignature.DetectionResult getPassiveDetection() { return passiveDetection; }
        public void setPassiveDetection(WAFSignature.DetectionResult passiveDetection) { 
            this.passiveDetection = passiveDetection; 
        }
        
        public List<ProbeResult> getProbeResults() { return new ArrayList<>(probeResults); }
        public void setProbeResults(List<ProbeResult> probeResults) { 
            this.probeResults = probeResults != null ? new ArrayList<>(probeResults) : new ArrayList<>(); 
        }
        
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        
        public String getSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("WAF Detection Result:\n");
            sb.append("  Detected: ").append(wafDetected ? "Yes" : "No").append("\n");
            if (wafDetected) {
                sb.append("  WAF Name: ").append(detectedWAF).append("\n");
                sb.append("  Confidence: ").append(confidence).append("%\n");
                sb.append("  Block Rate: ").append(String.format("%.1f%%", blockRate * 100)).append("\n");
            }
            if (error != null) {
                sb.append("  Error: ").append(error).append("\n");
            }
            return sb.toString();
        }
        
        public List<String> getRecommendedBypassTechniques() {
            List<String> techniques = new ArrayList<>();
            techniques.add("case_variation");
            techniques.add("encoding_chain");
            techniques.add("double_url_encode");
            techniques.add("unicode_encode");
            techniques.add("comment_injection");
            techniques.add("null_byte");
            techniques.add("chunked_encoding");
            return techniques;
        }
    }
}
