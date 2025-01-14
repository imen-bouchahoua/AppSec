package me.appsec;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Dependent;
import jakarta.enterprise.inject.Disposes;
import jakarta.enterprise.inject.Produces;
import jakarta.enterprise.inject.spi.InjectionPoint;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

import java.util.logging.Logger;

@ApplicationPath("/")
public class JAXRSApplication extends Application {
    @ApplicationScoped
    public static final class CDIConfigurator {
        @Produces
        @Dependent
        public Logger getLogger(InjectionPoint injectionPoint){
            return Logger.getLogger(injectionPoint.getBean().getBeanClass().getName());
        }

        public void disposeLogger(@Disposes Logger logger){
            logger.info("logger disposed!");
        }
    }
}