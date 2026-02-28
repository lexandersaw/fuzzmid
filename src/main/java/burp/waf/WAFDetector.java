package burp.waf;

import java.util.*;

public class WAFDetector {
    
    private final Map<String, WAFSignature> signatures;
    
    public WAFDetector() {
        this.signatures = new LinkedHashMap<>();
        initializeDefaultSignatures();
    }
    
    private void initializeDefaultSignatures() {
        // Cloudflare
        WAFSignature cloudflare = new WAFSignature("cloudflare", "Cloudflare");
        cloudflare.setVendor("Cloudflare");
        cloudflare.setType(WAFSignature.WAFType.CLOUD);
        cloudflare.addBypassTechnique("chunked_encoding");
        cloudflare.addBypassTechnique("case_variation");
        cloudflare.addBypassTechnique("unicode_normalization");
        
        WAFSignature.SignatureRule cfHeader = new WAFSignature.SignatureRule("cf-header", "Cloudflare header");
        cfHeader.setHeaderPattern("cf-ray|cloudflare");
        cfHeader.setWeight(30);
        cloudflare.addRule(cfHeader);
        
        WAFSignature.SignatureRule cfBody = new WAFSignature.SignatureRule("cf-body", "Cloudflare block page");
        cfBody.setBodyPattern("cloudflare|cf-browser-verification|cf_clearance");
        cfBody.setWeight(25);
        cloudflare.addRule(cfBody);
        
        addSignature(cloudflare);
        
        // ModSecurity
        WAFSignature modsec = new WAFSignature("modsecurity", "ModSecurity");
        modsec.setVendor("OWASP");
        modsec.setType(WAFSignature.WAFType.SOFTWARE);
        modsec.addBypassTechnique("comment_injection");
        modsec.addBypassTechnique("encoding_chain");
        modsec.addBypassTechnique("null_byte");
        modsec.addBypassTechnique("case_variation");
        
        WAFSignature.SignatureRule modsecHeader = new WAFSignature.SignatureRule("modsec-header", "ModSecurity header");
        modsecHeader.setHeaderPattern("mod_security|modsecurity");
        modsecHeader.setWeight(35);
        modsec.addRule(modsecHeader);
        
        WAFSignature.SignatureRule modsecBody = new WAFSignature.SignatureRule("modsec-body", "ModSecurity block page");
        modsecBody.setBodyPattern("mod_security|ModSecurity|Not Acceptable");
        modsecBody.setWeight(30);
        modsec.addRule(modsecBody);
        
        addSignature(modsec);
        
        // AWS WAF
        WAFSignature awswaf = new WAFSignature("awswaf", "AWS WAF");
        awswaf.setVendor("Amazon");
        awswaf.setType(WAFSignature.WAFType.CLOUD);
        awswaf.addBypassTechnique("chunked_encoding");
        awswaf.addBypassTechnique("http_version");
        awswaf.addBypassTechnique("encoding_variation");
        
        WAFSignature.SignatureRule awsHeader = new WAFSignature.SignatureRule("aws-header", "AWS WAF header");
        awsHeader.setHeaderPattern("x-amz-cf|x-amzn-requestid|aws-waf");
        awsHeader.setWeight(30);
        awswaf.addRule(awsHeader);
        
        WAFSignature.SignatureRule awsBody = new WAFSignature.SignatureRule("aws-body", "AWS WAF block page");
        awsBody.setBodyPattern("request blocked|access denied.*aws|cloudfront");
        awsBody.setWeight(25);
        awswaf.addRule(awsBody);
        
        addSignature(awswaf);
        
        // 安全狗
        WAFSignature safedog = new WAFSignature("safedog", "安全狗");
        safedog.setVendor("安全狗");
        safedog.setType(WAFSignature.WAFType.SOFTWARE);
        safedog.addBypassTechnique("double_url_encode");
        safedog.addBypassTechnique("unicode_encode");
        safedog.addBypassTechnique("h_w_event_attack");
        
        WAFSignature.SignatureRule safedogHeader = new WAFSignature.SignatureRule("safedog-header", "安全狗 header");
        safedogHeader.setHeaderPattern("safedog|safedogwaf");
        safedogHeader.setWeight(35);
        safedog.addRule(safedogHeader);
        
        WAFSignature.SignatureRule safedogBody = new WAFSignature.SignatureRule("safedog-body", "安全狗 block page");
        safedogBody.setBodyPattern("安全狗|safedog|拦截");
        safedogBody.setWeight(30);
        safedog.addRule(safedogBody);
        
        addSignature(safedog);
        
        // 云锁
        WAFSignature yunsuo = new WAFSignature("yunsuo", "云锁");
        yunsuo.setVendor("云锁");
        yunsuo.setType(WAFSignature.WAFType.SOFTWARE);
        yunsuo.addBypassTechnique("chunked_encoding");
        yunsuo.addBypassTechnique("multipart_boundary");
        yunsuo.addBypassTechnique("url_encode");
        
        WAFSignature.SignatureRule yunsuoHeader = new WAFSignature.SignatureRule("yunsuo-header", "云锁 header");
        yunsuoHeader.setHeaderPattern("yunsuo|yunsuo_session");
        yunsuoHeader.setWeight(35);
        yunsuo.addRule(yunsuoHeader);
        
        WAFSignature.SignatureRule yunsuoBody = new WAFSignature.SignatureRule("yunsuo-body", "云锁 block page");
        yunsuoBody.setBodyPattern("云锁|网站防火墙|yunsuo");
        yunsuoBody.setWeight(30);
        yunsuo.addRule(yunsuoBody);
        
        addSignature(yunsuo);
        
        // 绿盟 WAF
        WAFSignature nsfocus = new WAFSignature("nsfocus", "绿盟WAF");
        nsfocus.setVendor("绿盟科技");
        nsfocus.setType(WAFSignature.WAFType.HARDWARE);
        nsfocus.addBypassTechnique("encoding_chain");
        nsfocus.addBypassTechnique("case_variation");
        nsfocus.addBypassTechnique("comment_injection");
        
        WAFSignature.SignatureRule nsfocusHeader = new WAFSignature.SignatureRule("nsfocus-header", "绿盟 header");
        nsfocusHeader.setHeaderPattern("nsfocus|nsfocuswaf");
        nsfocusHeader.setWeight(35);
        nsfocus.addRule(nsfocusHeader);
        
        WAFSignature.SignatureRule nsfocusBody = new WAFSignature.SignatureRule("nsfocus-body", "绿盟 block page");
        nsfocusBody.setBodyPattern("绿盟|nsfocus|WAF拦截");
        nsfocusBody.setWeight(30);
        nsfocus.addRule(nsfocusBody);
        
        addSignature(nsfocus);
        
        // 启明星辰
        WAFSignature venustech = new WAFSignature("venustech", "启明星辰WAF");
        venustech.setVendor("启明星辰");
        venustech.setType(WAFSignature.WAFType.HARDWARE);
        venustech.addBypassTechnique("encoding_chain");
        venustech.addBypassTechnique("null_byte");
        
        WAFSignature.SignatureRule venusHeader = new WAFSignature.SignatureRule("venus-header", "启明星辰 header");
        venusHeader.setHeaderPattern("venustech|天清");
        venusHeader.setWeight(35);
        venustech.addRule(venusHeader);
        
        addSignature(venustech);
        
        // 安恒
        WAFSignature dbappsecurity = new WAFSignature("dbappsecurity", "安恒WAF");
        dbappsecurity.setVendor("安恒信息");
        dbappsecurity.setType(WAFSignature.WAFType.HARDWARE);
        dbappsecurity.addBypassTechnique("encoding_chain");
        dbappsecurity.addBypassTechnique("multipart_boundary");
        
        WAFSignature.SignatureRule dhBody = new WAFSignature.SignatureRule("dh-body", "安恒 block page");
        dhBody.setBodyPattern("安恒|dbappsecurity|WAF安全网关");
        dhBody.setWeight(35);
        dbappsecurity.addRule(dhBody);
        
        addSignature(dbappsecurity);
        
        // Naxsi
        WAFSignature naxsi = new WAFSignature("naxsi", "Naxsi");
        naxsi.setVendor("Naxsi");
        naxsi.setType(WAFSignature.WAFType.SOFTWARE);
        naxsi.addBypassTechnique("case_variation");
        naxsi.addBypassTechnique("encoding_variation");
        
        WAFSignature.SignatureRule naxsiBody = new WAFSignature.SignatureRule("naxsi-body", "Naxsi block page");
        naxsiBody.setBodyPattern("naxsi|blocked by naxsi|request denied");
        naxsiBody.setWeight(35);
        naxsi.addRule(naxsiBody);
        
        addSignature(naxsi);
        
        // Imperva
        WAFSignature imperva = new WAFSignature("imperva", "Imperva");
        imperva.setVendor("Imperva");
        imperva.setType(WAFSignature.WAFType.CLOUD);
        imperva.addBypassTechnique("chunked_encoding");
        imperva.addBypassTechnique("encoding_chain");
        
        WAFSignature.SignatureRule impervaCookie = new WAFSignature.SignatureRule("imperva-cookie", "Imperva cookie");
        impervaCookie.setHeaderPattern("incap_ses_|visid_incap");
        impervaCookie.setWeight(35);
        imperva.addRule(impervaCookie);
        
        addSignature(imperva);
        
        // F5 ASM
        WAFSignature f5asm = new WAFSignature("f5asm", "F5 ASM");
        f5asm.setVendor("F5 Networks");
        f5asm.setType(WAFSignature.WAFType.HARDWARE);
        f5asm.addBypassTechnique("encoding_chain");
        f5asm.addBypassTechnique("case_variation");
        
        WAFSignature.SignatureRule f5Body = new WAFSignature.SignatureRule("f5-body", "F5 block page");
        f5Body.setBodyPattern("support id|error.*reference.*id|blocked by.*f5");
        f5Body.setWeight(25);
        f5asm.addRule(f5Body);
        
        addSignature(f5asm);
        
        // Akamai
        WAFSignature akamai = new WAFSignature("akamai", "Akamai");
        akamai.setVendor("Akamai");
        akamai.setType(WAFSignature.WAFType.CDN);
        akamai.addBypassTechnique("chunked_encoding");
        akamai.addBypassTechnique("encoding_variation");
        
        WAFSignature.SignatureRule akamaiHeader = new WAFSignature.SignatureRule("akamai-header", "Akamai header");
        akamaiHeader.setHeaderPattern("akamai|x-akamai");
        akamaiHeader.setWeight(30);
        akamai.addRule(akamaiHeader);
        
        addSignature(akamai);
    }
    
    public void addSignature(WAFSignature signature) {
        if (signature != null && signature.getId() != null) {
            signatures.put(signature.getId(), signature);
        }
    }
    
    public void removeSignature(String id) {
        signatures.remove(id);
    }
    
    public WAFSignature getSignature(String id) {
        return signatures.get(id);
    }
    
    public List<WAFSignature> getAllSignatures() {
        return new ArrayList<>(signatures.values());
    }
    
    public List<WAFSignature.DetectionResult> detectAll(Map<String, String> headers, String responseBody, int responseCode) {
        List<WAFSignature.DetectionResult> results = new ArrayList<>();
        
        for (WAFSignature signature : signatures.values()) {
            WAFSignature.DetectionResult result = signature.detect(headers, responseBody, responseCode);
            if (result.isDetected()) {
                results.add(result);
            }
        }
        
        results.sort((a, b) -> Integer.compare(b.getScore(), a.getScore()));
        
        return results;
    }
    
    public WAFSignature.DetectionResult detectPrimary(Map<String, String> headers, String responseBody, int responseCode) {
        List<WAFSignature.DetectionResult> results = detectAll(headers, responseBody, responseCode);
        
        if (results.isEmpty()) {
            return new WAFSignature.DetectionResult(false, "Unknown", "Unknown", WAFSignature.WAFType.UNKNOWN, 0, new ArrayList<>());
        }
        
        return results.get(0);
    }
    
    public List<String> getBypassTechniques(String wafId) {
        WAFSignature signature = signatures.get(wafId);
        if (signature != null) {
            return signature.getBypassTechniques();
        }
        return new ArrayList<>();
    }
    
    public List<String> getAllBypassTechniques() {
        Set<String> techniques = new LinkedHashSet<>();
        for (WAFSignature signature : signatures.values()) {
            techniques.addAll(signature.getBypassTechniques());
        }
        return new ArrayList<>(techniques);
    }
}
