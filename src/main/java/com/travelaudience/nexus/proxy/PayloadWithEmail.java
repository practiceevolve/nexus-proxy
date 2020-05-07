package com.travelaudience.nexus.proxy;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.api.client.util.*;

public class PayloadWithEmail extends JsonWebToken.Payload {
    @Key("email")
    private String email;

    public String getEmail() {
        return email;
    }
}
