package org.daewon.phreview.security.exception;

import jakarta.persistence.EntityNotFoundException;

public class PharmacyNotFoundException extends EntityNotFoundException {
    public PharmacyNotFoundException() {
        super("유효하지 않은 약국 아이디입니다.");
    }
}