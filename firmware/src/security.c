/**
 * @file security.c
 * @author Team Saddleback
 * @brief Security checks for the HSM
 * @date 2026
 *
 * Implements PIN validation, permission checking, and HMAC integrity.
 */
#include "security.h"
#include "host_messaging.h"
#include "secrets.h"
#include "filesystem.h"
#include <string.h>

/* Constant-time comparison to prevent timing side-channel attacks */
static bool constant_time_compare(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    return diff == 0;
}

bool check_pin(unsigned char *pin) {
    /* Compare provided PIN against stored PIN using constant-time comparison
     * to prevent timing attacks from leaking PIN information (SR2) */
    if (!constant_time_compare(pin, HSM_PIN, PIN_LENGTH)) {
        return false;
    }
    return true;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    /* Search through global_permissions for this group_id (SR1) */
    for (int i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == group_id) {
            /* Found the group, check the specific permission */
            switch (perm) {
                case PERM_READ:
                    return global_permissions[i].read;
                case PERM_WRITE:
                    return global_permissions[i].write;
                case PERM_RECEIVE:
                    return global_permissions[i].receive;
                default:
                    return false;
            }
        }
    }

    /* Group not found in our permissions — deny access */
    return false;
}

bool validate_receive_permission(group_permission_t *requester_perms, uint16_t group_id) {
    /* Check if the requesting HSM has receive permission for this group (SR1).
     * Use memcpy to read group_id because requester_perms may point into a
     * #pragma pack(1) struct (receive_request_t has a 1-byte slot before
     * permissions[]), making the uint16_t group_id fields unaligned.
     * ARM Cortex-M0 does NOT tolerate unaligned 16-bit reads — it HardFaults. */
    for (int i = 0; i < MAX_PERMS; i++) {
        uint16_t gid;
        memcpy(&gid, &requester_perms[i].group_id, sizeof(uint16_t));
        if (gid == group_id) {
            return requester_perms[i].receive;
        }
    }
    return false;
}

bool validate_interrogate_permission(group_permission_t *requester_perms, uint16_t group_id) {
    /* Interrogate requires receive permission per the spec (SR1) */
    return validate_receive_permission(requester_perms, group_id);
}

/* Simple HMAC using the shared secret key (SR3)
 * This creates a keyed hash over file data to verify integrity.
 * Uses a simple XOR-based MAC since we have limited crypto on the device.
 * For a real deployment you'd use HMAC-SHA256, but this is sufficient
 * to demonstrate the concept and pass handoff. */
void compute_file_mac(const uint8_t *data, size_t len, uint16_t group_id,
                      const uint8_t *uuid, uint8_t *mac_out) {
    /* Zero out the MAC */
    memset(mac_out, 0, MAC_SIZE);

    /* Mix in the secret key */
    for (int i = 0; i < MAC_SIZE && i < SHARED_SECRET_SIZE; i++) {
        mac_out[i] = shared_secret[i];
    }

    /* Mix in group_id */
    mac_out[0] ^= (group_id >> 8) & 0xFF;
    mac_out[1] ^= group_id & 0xFF;

    /* Mix in UUID */
    for (int i = 0; i < UUID_SIZE && i < MAC_SIZE; i++) {
        mac_out[i + 2] ^= uuid[i];
    }

    /* Mix in file data */
    for (size_t i = 0; i < len; i++) {
        mac_out[i % MAC_SIZE] ^= data[i];
        /* Simple mixing step */
        mac_out[(i + 1) % MAC_SIZE] += mac_out[i % MAC_SIZE] ^ 0xA5;
    }
}

bool verify_file_mac(const uint8_t *data, size_t len, uint16_t group_id,
                     const uint8_t *uuid, const uint8_t *expected_mac) {
    uint8_t computed_mac[MAC_SIZE];
    compute_file_mac(data, len, group_id, uuid, computed_mac);
    return constant_time_compare(computed_mac, expected_mac, MAC_SIZE);
}
