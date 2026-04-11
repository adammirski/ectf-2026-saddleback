/**
 * @file security.c
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#include "security.h"
#include "host_messaging.h"
#include "secrets.h"
#include <string.h>
#include <stddef.h>

bool check_pin(unsigned char *pin) {
    return memcmp(pin, HSM_PIN, PIN_LENGTH) == 0;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    for (int i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == group_id) {
            switch (perm) {
                case PERM_READ:    return global_permissions[i].read;
                case PERM_WRITE:   return global_permissions[i].write;
                case PERM_RECEIVE: return global_permissions[i].receive;
                default: return false;
            }
        }
    }
    return false;
}

bool requester_can_receive(const group_permission_t *perms, uint16_t group_id) {
    /* `perms` points into a #pragma pack(1) struct, so each element may sit
     * on an odd address. Cortex-M0+ faults on unaligned halfword loads, so
     * access each field via byte pointers rather than struct member reads.
     * Keep this function's own stack usage at zero — listen() is already
     * way over the 256-byte stack limit with its recv_resp local. */
    const uint8_t *src = (const uint8_t *)perms;
    for (int i = 0; i < MAX_PERMS; i++) {
        const uint8_t *e = src + i * sizeof(group_permission_t);
        uint16_t gid = (uint16_t)e[0] | ((uint16_t)e[1] << 8);
        if (gid == group_id && e[offsetof(group_permission_t, receive)]) {
            return true;
        }
    }
    return false;
}
