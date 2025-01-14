package me.appsec.security;

import jakarta.ejb.EJBException;
import jakarta.ejb.LocalBean;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.json.Json;
import jakarta.json.JsonObject;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;

@Startup
@Singleton
@LocalBean
public class JwtManager implements me.appsec.JwtManager {

    private final static String curve = "Ed25519";
    private final static KeyPairGenerator keyPairGenerator;
    private final static Signature signatureAlgorithm;

    static{
        try{
            keyPairGenerator= KeyPairGenerator.getInstance(curve);
            signatureAlgorithm= Signature.getInstance(curve);
        }catch (NoSuchAlgorithmException e){
            throw  new EJBException(e);
        }
    }
    private final Map<String, KeyPair> cachedKeyPair = new HashMap<>();
    private final Map<String, Long> keyPairExpires = new HashMap<>();  // temps d'expiration de la clé privée
    private final long keyPairLifeTime= 10800; // 3h
    private final long jwtLifeTime=1020; // 17 min
    private final long maxCacheSize=3;  // nb des pair de clés
    private  final Set<String> audiences = Set.of("urn:me.appsecarmi.www","urn:appsecarmi.admin");
    private String issuer = "urn:me.appsecmi.iam";


    private void generateKeyPair(){
        var kid = UUID.randomUUID().toString();
        keyPairExpires.put(kid, Instant.now().getEpochSecond()+keyPairLifeTime);
        cachedKeyPair.put(kid,keyPairGenerator.generateKeyPair());
    }
    private Optional<Map.Entry<String, KeyPair>> getKeyPair(){
        cachedKeyPair.entrySet().removeIf(e -> isPublicKeyExpired(e.getKey()));
        while (cachedKeyPair.entrySet().stream().filter(e -> privateKeyHasNotExpired(e.getKey())).count() < maxCacheSize ) {
            generateKeyPair();
        }
        return cachedKeyPair.entrySet().stream().filter(e -> privateKeyHasNotExpired(e.getKey())).findAny();
    }


    private boolean isPublicKeyExpired(String kid) {
        return Instant.now().getEpochSecond() > (keyPairExpires.get(kid)+jwtLifeTime);
    }
    private boolean privateKeyHasNotExpired(String kid) {
        return Instant.now().getEpochSecond() < (keyPairExpires.get(kid));
    }
    @Override
    public String generateToken(String clientId, String subject, String approvedScopes, String[] roles){
        try {
            var keyPair = getKeyPair().orElseThrow();
            var privateKey = keyPair.getValue().getPrivate();
            signatureAlgorithm.initSign(privateKey);
            /* header */
            var header = Json.createObjectBuilder()
                    .add("typ", "JWT")
                    .add("alg", privateKey.getAlgorithm())
                    .add("kid",keyPair.getKey())
                    .build().toString();
            /* payload */
            var now = Instant.now();
            // roles
            var rolesJab = Json.createArrayBuilder();
            for (var role: roles){
                rolesJab.add(role);
            }
            var audiencesJab= Json.createArrayBuilder();
            for(var audience : audiences){
                audiencesJab.add(audience);
            }
            var payload = Json.createObjectBuilder()
                    .add("iss", issuer)
                    .add("add",audiencesJab)
                    .add("client-id",clientId)
                    .add("sub",subject)
                    .add("upn",subject)
                    .add("scope",approvedScopes)
                    .add("groups",rolesJab)
                    .add("exp",now.getEpochSecond()+jwtLifeTime)
                    .add("iat",now.getEpochSecond())
                    .add("nbf",now.getEpochSecond())
                    .add("jti",UUID.randomUUID().toString())
                    .build().toString();
            /* signature */
            var toSing= Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes())
                    +"."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());
            signatureAlgorithm.update(toSing.getBytes(StandardCharsets.UTF_8));
            return toSing+"."+Base64.getUrlEncoder().withoutPadding().encodeToString(signatureAlgorithm.sign());
        } catch (InvalidKeyException | SignatureException e) {
            throw new EJBException(e);
        }
    }
    @Override
    public Map<String,String> verifyToken (String token){
        var parts= token.split("\\.");
        // getting the header to extract to kid to the public key
        var header = Json.createReader(new StringReader(new String(Base64.getUrlDecoder().decode(parts[0])))).readObject();
        var kid = header.getString("kid");
        if(kid == null){
            throw new EJBException("Invalid token");
        }
        var keyPair = cachedKeyPair.get(kid);
        if(keyPair==null){
            return Collections.emptyMap();
        }
        try {
            signatureAlgorithm.initVerify(keyPair.getPublic());
            signatureAlgorithm.update((parts[0]+"."+parts[1]).getBytes(StandardCharsets.UTF_8));
            // verifying the signature
            if(!signatureAlgorithm.verify(Base64.getUrlDecoder().decode(parts[2]))) {
                return Collections.emptyMap();
            }
            var payload = Json.createReader(new StringReader(new String(Base64.getUrlDecoder().decode(parts[1])))).readObject();
            var exp = payload.getJsonNumber("exp");
            // verifying the expiration date
            if(exp == null){
                throw new EJBException("Invalid token");
            }
            if(Instant.ofEpochSecond(exp.longValue()).isBefore(Instant.now())){
                return Collections.emptyMap();
            }
            return Map.of("client-id",payload.getString("client-id"),
                    "sub", payload.getString("sub"),
                    "upn",payload.getString("upn"),
                    "scope", payload.getString("scope"),
                    "groups", payload.getJsonArray("groups").toString());
        } catch (SignatureException | InvalidKeyException e) {
            throw new EJBException(e);
        }

    }
    @Override
    public JsonObject getPublicKeyAsJWK(String kid) {
        var keyPair = cachedKeyPair.get(kid);
        if(keyPair== null){
            throw new EJBException("Kid invalid");
        }
        var encoded = Base64.getUrlEncoder().withoutPadding().encodeToString((keyPair.getPublic().getEncoded()));
        return Json.createObjectBuilder()
                .add("kty","EC")
                .add("crv",curve)
                .add("kid",kid)
                .add("x",encoded.substring(16))
                .build();
    }
}