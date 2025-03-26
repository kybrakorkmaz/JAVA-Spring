package com.korkmaz.kubra.auth.enumerate;

import lombok.Getter;

@Getter
public enum EmailTemplate {

    ACTIVATE_ACCOUNT("activate_account")
    ;
    private final String template;
    EmailTemplate(String template) {
        this.template = template;
    }
}
