package me.appsec.models;

import java.io.Serializable;

public interface RootEntity<ID extends Serializable> extends Serializable {
    ID getID();
    void setID(ID id);
}
