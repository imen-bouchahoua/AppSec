package me.appsec.boundaries;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import me.appsec.repositories.IAMRepository;
import me.appsec.security.authorizationCode.AuthorizationCode;
import me.appsec.models.grant.Grant;
import me.appsec.models.user.User;
import me.appsec.security.Argon2Utility;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.logging.Logger;


@Path("/")
@RequestScoped
public class AuthorizationEndpoint {

    @Inject
    private IAMRepository iamRepository;

    @Inject
    private Logger logger;

    public static final String CHALLENGE_RESPONSE_COOKIE_ID = "signInId";

    @GET
    public String HelloWord(){
        logger.info("HelloWord called");
        return "Hello word!";
    }

    @POST
    @Path("/password")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String generatePassword(@FormParam("password")String password) {
            char[] clientHashChars = password.toCharArray();
            return Argon2Utility.hash(clientHashChars);
    }

    @Path("/authorize")
    @Produces(MediaType.TEXT_HTML)
    @GET
    public Response authorize(@Context UriInfo uriInfo){
        var params = uriInfo.getQueryParameters();
        //1. Check client ID
        var clientId = params.getFirst("client_id");
        if (clientId == null || clientId.isEmpty()) {
            return informUserAboutError("Invalid client_id :" + clientId);
        }

        if(iamRepository.findClientByClientId(clientId).isEmpty()){
            return informUserAboutError("Invalid client_id :" + clientId);
        }
        var client = iamRepository.findClientByClientId(clientId).get();
        //2. Client Authorized Grant Type
        if(client.getSupportedGrantTypes() !=null && !client.getSupportedGrantTypes().contains("authorization_code")){
            return informUserAboutError("Authorization Grant type, authorization_code, is not allowed for this client :" + clientId);
        }
        //3. redirectUri
        String redirectUri = params.getFirst("redirect_uri");
        if(client.getRedirectUris() !=null && !client.getRedirectUris().isEmpty()){
            if (redirectUri != null && !redirectUri.isEmpty() && !client.getRedirectUris().equals(redirectUri)){
                return informUserAboutError("redirect_uri is pre-registred and should match");
            }
            redirectUri = client.getRedirectUris();
        }else{
            if(redirectUri==null || redirectUri.isEmpty()){
                return informUserAboutError("redirect_uri is not pre-registred and should be provided");
            }
        }
        //4. response_type
        String responseType = params.getFirst("response_type");
        if (!"code".equals(responseType) && !"token".equals(responseType)) {
            String error = "invalid_grant :" + responseType + ", response_type params should be code or token:";
            return informUserAboutError(error);
        }
        //5. check scope
        String requestedScope = params.getFirst("scope");
        if (requestedScope == null || requestedScope.isEmpty()) {
            requestedScope = client.getRequiredScopes();
        }
        //6. code_challenge_method must be S256
        String codeChallengeMethod = params.getFirst("code_challenge_method");
        if(codeChallengeMethod==null || !codeChallengeMethod.equals("S256")){
            String error = "invalid_grant :" + codeChallengeMethod + ", code_challenge_method must be 'S256'";
            return informUserAboutError(error);
        }

        // cookie creation
        NewCookie cookie = new NewCookie.Builder(CHALLENGE_RESPONSE_COOKIE_ID)
                .httpOnly(true) // accessible uniquement via HTTP
                .secure(false) // pour le test
                .secure(true)   // via HTTPS
                .sameSite(NewCookie.SameSite.STRICT)
                .value(client.getClientId()+"#"+requestedScope+"$"+redirectUri)
                .build();

        StreamingOutput stream = output -> {
            try (InputStream is = Objects.requireNonNull(getClass().getResource("/login.html")).openStream()){
                output.write(is.readAllBytes());
            }
        };
        return Response.ok(stream)
                .location(uriInfo.getBaseUri().resolve("/login/authorization"))
                .cookie(cookie)
                .build();
    }

    @POST
    @Path("/login/authorization")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    public Response login(@CookieParam(CHALLENGE_RESPONSE_COOKIE_ID) Cookie cookie,
                          @FormParam("username")String username,
                          @FormParam("password")String password,
                          @Context UriInfo uriInfo) throws Exception{

        // validate entries
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Username and password are required.")
                    .build();
        }
        // info from cookie
        String redirectUri = cookie.getValue().split("\\$")[1];
        String clientId = cookie.getValue().split("#")[0];
        String requestedScopes = cookie.getValue().split("#")[1].split("\\$")[0];

        try{

            Optional<User> optionalUser = iamRepository.findUserByUsername(username);
            if (optionalUser.isPresent()) {
                User user = optionalUser.get();

                if (Argon2Utility.check(user.getPassword(), password.toCharArray())) {
                    logger.info("Authenticated identity:" + username);
                    MultivaluedMap<String, String> params = uriInfo.getQueryParameters();

                    // retrieving the grant
                    Optional<Grant> grant = iamRepository.findGrant(clientId, user.getID());
                    if (grant.isPresent()) {
                        String redirectedURI = buildActualRedirectURI(
                                redirectUri, // redirectUri
                                params.getFirst("response_type"),     // response_type
                                clientId,                                // clientID
                                username,                                // userID
                                checkUserScopes(grant.get().getApprovedScopes(), requestedScopes),  //approved_scopes
                                params.getFirst("code_challenge"),   // code_challenge
                                params.getFirst("state")
                        );
                        logger.info("Redirecting to: " + redirectedURI);
                        //                return Response.seeOther(UriBuilder.fromUri(redirectedURI).build()).build();
                        return Response.ok(redirectedURI).build();
                    } else {
                        //                StreamingOutput stream = output -> {
                        //                    try (InputStream is = getClass().getResourceAsStream("/consent.html")) {
                        //                        Objects.requireNonNull(is, "Resource not found: /consent.html");
                        //                        String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                        //                        String updatedContent = content.replace("{{username}}", URLEncoder.encode(username, StandardCharsets.UTF_8));
                        //                        output.write(updatedContent.getBytes(StandardCharsets.UTF_8));
                        //                    }
                        //                };
                        String consentPageUrl = uriInfo.getBaseUri()
                                + "consent?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                                + "&response_type=" + params.getFirst("response_type")
                                + "&code_challenge=" + params.getFirst("code_challenge")
                                + "&state=" + params.getFirst("state");
                        return Response.ok(consentPageUrl).build();
                    }


                } else {
                    logger.info("Failure when authenticating identity: " + username);
                    return Response.status(Response.Status.FORBIDDEN) // Code 403
                            .entity("Authentication failed: invalid credentials or user not approved.")
                            .build();
                }
            }else {
                logger.info("Failure when authenticating identity: " + username);
                return Response.status(Response.Status.FORBIDDEN) // Code 403
                        .entity("Incorrect username or password.")
                        .build();
            }
        }catch (Exception e){
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("An error occurred during the authentication process.")
                    .build();
        }
    }

    @PATCH
    @Path("/login/authorization")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response grantConsent(@CookieParam(CHALLENGE_RESPONSE_COOKIE_ID) Cookie cookie,
                                 @FormParam("approved_scope") String scope,
                                 @FormParam("approval_status") String approvalStatus,
                                 @FormParam("username") String username,
                                 @FormParam("frontend_url") String frontendUrl){
        String redirectUri = cookie.getValue().split("\\$")[1];
        String clientId = cookie.getValue().split("#")[0];

        String query = frontendUrl.split("\\?")[1];

        String[] queryParams = query.split("&");

        String responseType = null;
        String codeChallenge = null;
        String state = null;

        // Boucler sur chaque paramètre
        for (String param : queryParams) {
            String[] pair = param.split("=");
            if (pair.length == 2) {
                String key = pair[0];
                String value = pair[1];

                if ("response_type".equals(key)) {
                    responseType = value;
                } else if ("code_challenge".equals(key)) {
                    codeChallenge = value;
                } else if ("state".equals(key)) {
                    state = value;
                }
            }
        }

        // Log des valeurs extraites
        logger.info("response_type: " + responseType);
        logger.info("code_challenge: " + codeChallenge);
        logger.info("state: " + state);
        // if NO
        if("NO".equals(approvalStatus)){
            logger.info("Grant refused :"+username);
            URI location= UriBuilder.fromUri(redirectUri)
                    .queryParam("error", "User doesn't approved the request.")
                    .queryParam("error_description", "User doesn't approved the request.")
                    .build();
            return Response.seeOther(location).build();
        }
        // if YES
        List<String> approvedScopes = Arrays.stream(scope.split(" ")).toList();
        if(approvedScopes.isEmpty()){
            logger.info("Grant refused :"+username);
            URI location= UriBuilder.fromUri(redirectUri)
                    .queryParam("error", "User doesn't approved the request.")
                    .queryParam("error_description", "User doesn't approved the request.")
                    .build();
            return Response.seeOther(location).build();
        }
        try {
            Long userId = iamRepository.findUserByUsername(username).map(User::getID).orElse(null);
            Optional<Grant> grant = iamRepository.addGrant(clientId, userId, String.join(" ", approvedScopes));
            logger.info("Grant added :"+username);

            String redirectedURI =
                    buildActualRedirectURI(
                            redirectUri,
                            responseType,
                            clientId,
                            username,
                            String.join(" ",approvedScopes),
                            codeChallenge,
                            state
                            );
            return Response.ok(redirectedURI).build();

        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    @GET
    @Path("/consent")
    @Produces(MediaType.TEXT_HTML)
    public Response getConsentPage(@QueryParam("username") String username) throws IOException {
        InputStream is = getClass().getResourceAsStream("/consent.html");
        String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        content = content.replace("{{username}}", username);
        return Response.ok(content).build();
    }
    private String checkUserScopes(String approvedScopes, String requestedScopes) {
        Set<String> allowedScopes = new LinkedHashSet<>();
        Set<String> rScopes = new HashSet<>(Arrays.asList(requestedScopes.split(" ")));
        Set<String> uScopes = new HashSet<>(Arrays.asList(approvedScopes.split(" ")));
        for (String scope: uScopes){
            if (rScopes.contains(scope)) allowedScopes.add(scope);
        }
        return String.join(" ",allowedScopes);
    }

    private String buildActualRedirectURI(
            String redirectUri,
            String responseType,
            String clientId,
            String userId,
            String approvedScopes,
            String codeChallenge,
            String state) throws Exception {
        StringBuilder sb = new StringBuilder(redirectUri);
        if ("code".equals(responseType)) {
            AuthorizationCode authorizationCode = new AuthorizationCode(
                    clientId,
                    userId,
                    approvedScopes,
                    Instant.now().plus(2, ChronoUnit.MINUTES).getEpochSecond(),
                    redirectUri);
            sb.append("?code=").append(URLEncoder.encode(authorizationCode.getCode(codeChallenge), StandardCharsets.UTF_8));

        } else {
            //Implicit: responseType=token : Not Supported
            return null;
        }
        if (state != null) {
            sb.append("&state=").append(state);
        }
        return sb.toString();
    }

    private Response informUserAboutError(String error) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity("""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8"/>
                    <title>Error</title>
                </head>
                <body>
                <aside class="container">
                    <p>%s</p>
                </aside>
                </body>
                </html>
                """.formatted(error))
                .type("text/html")
                .build();
    }
}