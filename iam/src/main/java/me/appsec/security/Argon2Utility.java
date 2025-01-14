package me.appsec.security;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import jakarta.security.enterprise.identitystore.PasswordHash;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

public class Argon2Utility implements PasswordHash {

    private static final Config config = ConfigProvider.getConfig();
    private static final int saltLength= config.getValue("argon2.saltLength", Integer.class);
    private static  final int hashLength = config.getValue("argon2.hashLength", Integer.class);
    private static final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id,saltLength,hashLength);

    private static final int iterations = config.getValue("argon2.iterations",Integer.class);
    private static final int memory = config.getValue("argon2.memory",Integer.class);
    private static final int threads = config.getValue("argon2.threads",Integer.class);
    public static String hash(char[] clientHash){
        try {
            return argon2.hash(iterations,memory,threads,clientHash);
        }finally {
            argon2.wipeArray(clientHash);
        }
    }
    public static boolean check(String serverHash, char[] clientHash){
        try {
            return argon2.verify(serverHash,clientHash);
        }finally {
            argon2.wipeArray(clientHash);
        }
    }
    @Override
    public String generate(char[] password) {
        return hash(password);
    }

    @Override
    public boolean verify(char[] password, String hashedPassword) {
        return check(hashedPassword,password);
    }
}
