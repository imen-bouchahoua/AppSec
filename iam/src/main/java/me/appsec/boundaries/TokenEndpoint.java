package me.appsec.boundaries;

import jakarta.ejb.EJB;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import me.appsec.repositories.IAMRepository;
import me.appsec.security.authorizationCode.AuthorizationCode;
import me.appsec.security.JwtManager;
import jakarta.json.JsonString;
import org.eclipse.microprofile.config.ConfigProvider;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.logging.Logger;

@Path("/oauth/token")
public class TokenEndpoint {

    @Inject
    private Logger logger;
    @Inject
    private IAMRepository iamRepository;
    @EJB
    private JwtManager jwtManager;
    private final Set<String> supportedGrantTypes = Set.of("authorization_code", "refresh_token");

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response token(@FormParam("grant_type") String grantType,
                          @FormParam("code") String authCode,
                          @FormParam("code_verifier") String codeVerifier) {
        logger.info("Received request with grant_type: " + grantType);
        logger.info("authCode: " + authCode);  // Log de authCode
        logger.info("codeVerifier: " + codeVerifier);  // Log de codeVerifier
        if (grantType == null || grantType.isEmpty()) {
            return responseError("Invalid_request", "grant_type is required", Response.Status.BAD_REQUEST);
        }
        // refresh code
        if ("refresh_token".equals(grantType)) {
            var previousAccessToken = jwtManager.verifyToken(authCode);
            var previousRefreshToken = jwtManager.verifyToken(codeVerifier);
            if (!previousAccessToken.isEmpty() && !previousRefreshToken.isEmpty()) {
                try {
                    var clientId = previousAccessToken.get("client_id");
                    var scopes = previousAccessToken.get("scope");
                    var subject = previousAccessToken.get("sub");
                    var roles = Json.createReader(new StringReader(previousAccessToken.get("groups"))).readArray().getValuesAs(JsonString.class).stream().map(JsonString::getString).toList().toArray(new String[0]);

                    var refreshClientId = previousRefreshToken.get("client_id");
                    var refreshScopes = previousRefreshToken.get("scope");
                    var refreshSubject = previousRefreshToken.get("sub");

                    var accessToken = jwtManager.generateToken(clientId, subject, scopes, roles);
                    var refreshToken = jwtManager.generateToken(clientId, subject, scopes, new String[]{"refresh_role"});
                    if (refreshScopes.equals(scopes) &&
                            refreshClientId.equals(clientId) &&
                            refreshSubject.equals(subject)) {
                        return Response.ok(Json.createObjectBuilder()
                                        .add("token_type", "Bearer")
                                        .add("access_token", accessToken)
                                        .add("expires_in", ConfigProvider.getConfig().getValue("jwt.lifetime.duration", Integer.class))
                                        .add("scope", scopes)
                                        .add("refresh_token", refreshToken)
                                        .build())
                                .header("Cache-Control", "no-store")
                                .header("Pragma", "no-cache")
                                .build();
                    } else {
                        return responseError("Invalid_request", "Can't get token", Response.Status.UNAUTHORIZED);
                    }
                } catch (Exception e) {
                    throw new WebApplicationException(e);
                }

            }
        }
        // authorization code
        try {
            logger.info("Processing authorization code flow...");
            AuthorizationCode decoded = AuthorizationCode.decode(authCode, codeVerifier);

            assert decoded != null;
            logger.info("Decoded authorization code successfully.");

            String accessToken = jwtManager.generateToken(decoded.clientId(), decoded.username(), decoded.approvedScopes(), iamRepository.getRoles(decoded.username()));
            String refreshToken = jwtManager.generateToken(decoded.clientId(), decoded.username(), decoded.approvedScopes(), new String[]{"refresh_role"});
            logger.info("Generated access_token: " + accessToken);
            logger.info("Generated refresh_token: " + refreshToken);
            return Response.ok(Json.createObjectBuilder()
                                .add("token_type", "Bearer")
                                .add("access_token", accessToken)
                                .add("expires_in", ConfigProvider.getConfig().getValue("jwt.lifetime.duration", Integer.class))
                                .add("scope", decoded.approvedScopes())
                                .add("refresh_token", refreshToken)
                                .build())
                        .header("Cache-Control", "no-store")
                        .header("Pragma", "no-cache")
                        .build();

        }
        catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
        }
        catch (Exception e) {
                throw new RuntimeException(e);
        }

    }

    private Response responseError (String error, String errorDescription, Response.Status status){
        JsonObject errorResponse = Json.createObjectBuilder()
                .add("error", error)
                .add("error_description", errorDescription)
                .build();
        return Response.status(status)
                .entity(errorResponse).build();
    }
}