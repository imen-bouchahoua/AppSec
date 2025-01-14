package me.appsec.configuration;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;

import java.io.IOException;

@Provider
public class CorsFilter implements ContainerResponseFilter {

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        // Ajoute l'en-tête Access-Control-Allow-Origin pour autoriser les requêtes depuis 127.0.0.1:3002
        responseContext.getHeaders().add("Access-Control-Allow-Origin", "*");

        // Ajoute l'en-tête Access-Control-Allow-Methods pour autoriser les méthodes HTTP spécifiques
        responseContext.getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");

        // Ajoute l'en-tête Access-Control-Allow-Headers pour autoriser les en-têtes spécifiques
        responseContext.getHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");

        responseContext.getHeaders().add("Access-Control-Allow-Credentials", "true");
    }
}
