package me.appsec.models.user;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.eclipse.microprofile.config.ConfigProvider;


public enum Role {

    GUEST(0L),
    R_P00(1L),
    R_P01(1L<<1L),
    ROOT(Long.MAX_VALUE);

    private final long value;

    /** constructor */
    Role(long value){
        this.value = value;
    }
    public long getValue() {
        return value;
    }

    private static final Map<Long,String> ids = new LinkedHashMap<>();
    private static final Map<String,Role> byIds = new LinkedHashMap<>();

    static {
        final AtomicLong id = new AtomicLong(1L);
        List<String> customRoles = ConfigProvider.getConfig().getValues("roles",String.class);
        if(customRoles.stream().anyMatch(r -> r.equalsIgnoreCase(GUEST.name())||r.equalsIgnoreCase(ROOT.name()))
                ||customRoles.size()>62){
            throw new IllegalArgumentException("Illegal config value for roles");
        }
        ids.putAll(customRoles.stream().collect(Collectors.toMap(x -> id.getAndUpdate(y -> 2L*y),Function.identity())));
        ids.put(GUEST.value, GUEST.name().toLowerCase());
        ids.put(ROOT.value, ROOT.name().toLowerCase());
        final AtomicInteger ordinal = new AtomicInteger(1);
        final Role[] values = Role.values();
        byIds.put(GUEST.name().toLowerCase(),GUEST);
        byIds.put(ROOT.name().toLowerCase(),ROOT);
        byIds.putAll(customRoles.stream().collect(Collectors.toMap(Function.identity(), x -> values[ordinal.getAndIncrement()])));
    }
    public final String id(){
        return ids.get(value);
    }

    public static String byValue(Long value){
        return ids.get(value);
    }

    public static Role byId(String id){
        return byIds.get(id);
    }

}
