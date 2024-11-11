package com.example.OAuth2JWT.dto;

import java.util.Map;

public class SeungResponse implements OAuth2Response{

    private final Map<String, Object> attribute;

    public SeungResponse(Map<String, Object> attribute) {
        this.attribute = (Map<String, Object>) attribute.get("response");
    }


    @Override
    public String getProvider() {
        return "seung";
    }

    @Override
    public String getProviderId() {
        //임시
        return "123123123";
    }

    @Override
    public String getEmail() {
        return attribute.get("username").toString() + "@seung.com";
    }

    @Override
    public String getName() {
        return attribute.get("username").toString();
    }
}
