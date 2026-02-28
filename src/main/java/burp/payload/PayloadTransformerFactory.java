package burp.payload;

import java.util.ArrayList;
import java.util.List;

public class PayloadTransformerFactory {
    
    public static List<PayloadTransformer> getEncodingTransformers() {
        List<PayloadTransformer> transformers = new ArrayList<>();
        transformers.add(new NoTransformTransformer());
        transformers.add(new UrlEncodeTransformer());
        transformers.add(new UrlEncodeAllTransformer());
        transformers.add(new DoubleUrlEncodeTransformer());
        transformers.add(new Base64EncodeTransformer());
        transformers.add(new HtmlEncodeTransformer());
        transformers.add(new UnicodeEncodeTransformer());
        transformers.add(new HexEncodeTransformer());
        return transformers;
    }
    
    public static List<PayloadTransformer> getCaseTransformers() {
        List<PayloadTransformer> transformers = new ArrayList<>();
        transformers.add(new NoTransformTransformer());
        transformers.add(new UpperCaseTransformer());
        transformers.add(new LowerCaseTransformer());
        transformers.add(new RandomCaseTransformer());
        return transformers;
    }
    
    public static List<PayloadTransformer> getWrapTransformers() {
        List<PayloadTransformer> transformers = new ArrayList<>();
        transformers.add(new NoTransformTransformer());
        transformers.add(new AddQuotesTransformer());
        transformers.add(new WrapCommentTransformer());
        return transformers;
    }
    
    public static List<PayloadTransformer> getAllTransformers() {
        List<PayloadTransformer> transformers = new ArrayList<>();
        transformers.addAll(getEncodingTransformers());
        transformers.addAll(getCaseTransformers());
        transformers.addAll(getWrapTransformers());
        return transformers;
    }
    
    public static PayloadTransformer createTransformer(PayloadTransformer.TransformType type) {
        return createTransformer(type, "");
    }
    
    public static PayloadTransformer createTransformer(PayloadTransformer.TransformType type, String param) {
        switch (type) {
            case URL_ENCODE:
                return new UrlEncodeTransformer();
            case URL_ENCODE_ALL:
                return new UrlEncodeAllTransformer();
            case DOUBLE_URL_ENCODE:
                return new DoubleUrlEncodeTransformer();
            case BASE64_ENCODE:
                return new Base64EncodeTransformer();
            case HTML_ENCODE:
                return new HtmlEncodeTransformer();
            case UNICODE_ENCODE:
                return new UnicodeEncodeTransformer();
            case HEX_ENCODE:
                return new HexEncodeTransformer();
            case UPPER_CASE:
                return new UpperCaseTransformer();
            case LOWER_CASE:
                return new LowerCaseTransformer();
            case RANDOM_CASE:
                return new RandomCaseTransformer();
            case ADD_PREFIX:
                return new AddPrefixTransformer(param);
            case ADD_SUFFIX:
                return new AddSuffixTransformer(param);
            case ADD_QUOTES:
                return new AddQuotesTransformer();
            case WRAP_COMMENT:
                return new WrapCommentTransformer();
            case NONE:
            default:
                return new NoTransformTransformer();
        }
    }
    
    public static List<String> transformList(List<String> payloads, PayloadTransformer transformer) {
        List<String> result = new ArrayList<>();
        for (String payload : payloads) {
            result.add(transformer.transform(payload));
        }
        return result;
    }
    
    public static List<String> transformWithMultiple(List<String> payloads, List<PayloadTransformer> transformers) {
        List<String> result = new ArrayList<>();
        for (String payload : payloads) {
            String transformed = payload;
            for (PayloadTransformer transformer : transformers) {
                transformed = transformer.transform(transformed);
            }
            result.add(transformed);
        }
        return result;
    }
    
    public static List<String> generateVariants(String payload, List<PayloadTransformer> transformers) {
        List<String> variants = new ArrayList<>();
        variants.add(payload);
        for (PayloadTransformer transformer : transformers) {
            if (!(transformer instanceof NoTransformTransformer)) {
                variants.add(transformer.transform(payload));
            }
        }
        return variants;
    }
    
    public static List<String> generateAllVariants(List<String> payloads) {
        List<String> allVariants = new ArrayList<>();
        List<PayloadTransformer> encoders = getEncodingTransformers();
        List<PayloadTransformer> caseTransformers = getCaseTransformers();
        
        for (String payload : payloads) {
            for (PayloadTransformer encoder : encoders) {
                String encoded = encoder.transform(payload);
                for (PayloadTransformer caseTransformer : caseTransformers) {
                    allVariants.add(caseTransformer.transform(encoded));
                }
            }
        }
        
        return allVariants;
    }
}
