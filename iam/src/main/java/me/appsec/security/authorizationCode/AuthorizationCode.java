package me.appsec.security.authorizationCode;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

public record AuthorizationCode(
        String clientId,
        String username,
        String approvedScopes,
        Long expirationDate,
        String redirectUri){
    private static final SecretKey key;
    private static final String codePrefix = "urn:secugate:code:";

    static {
        try{
            key= KeyGenerator.getInstance("CHACHA20").generateKey();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public String getCode(String codeChallenge) throws Exception {
        String code = UUID.randomUUID().toString();

        String payload = Base64.getEncoder().withoutPadding().encodeToString(
                (clientId+":"+username+":"+approvedScopes+":"+expirationDate+":"+redirectUri).getBytes(StandardCharsets.UTF_8)
        );
        String associatedData = codePrefix+code;
        code= codePrefix+code+":"+payload;
        return code+":"+Base64.getEncoder().withoutPadding().encodeToString(ChaCha20Poly1305.encrypt(codeChallenge.getBytes(),key));
    }
    public static AuthorizationCode decode(String authorizationCode, String codeVerifier) throws Exception{
        int pos = authorizationCode.lastIndexOf(":");
        String code = authorizationCode.substring(0,pos);
        String cipherCodeChallenge = authorizationCode.substring(pos+1);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(codeVerifier.getBytes(StandardCharsets.UTF_8));
        String expected= Base64.getEncoder().withoutPadding().encodeToString(digest.digest());

        if(!expected.equals(new String(ChaCha20Poly1305.decrypt(Base64.getDecoder().decode(cipherCodeChallenge),key),StandardCharsets.UTF_8).replace("_","/").replace("-","+"))){
            System.out.println(expected+" ?= "+ new String(ChaCha20Poly1305.decrypt(Base64.getDecoder().decode(cipherCodeChallenge),key),StandardCharsets.UTF_8));
            return null;
        }
        // prefix
        code = code.substring(codePrefix.length());
        pos = code.lastIndexOf(":");
        // payload
        String payload = new String(Base64.getDecoder().decode(code.substring(pos + 1)), StandardCharsets.UTF_8);
        String[] attributes = payload.split(":");
        if (attributes.length != 7) {
            throw new IllegalArgumentException("Invalid payload structure." + payload);
        }
        // Construction de l'objet AuthorizationCode
        return new AuthorizationCode(
                attributes[0],
                attributes[1],
                attributes[2],
                Long.parseLong(attributes[3]),
                attributes[4]+":"+attributes[5]+":"+attributes[6]
        );
    }
}