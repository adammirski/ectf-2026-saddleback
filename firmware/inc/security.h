/**
 * @file security.h
 * @author Team Saddleback
 * @brief Security checks for the HSM
 * @date 2026
 */
#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define MAX_PERMS 8
#define PIN_LENGTH 6
#define MAC_SIZE 16

typedef enum {
    PERM_READ = 'R',
    PERM_WRITE = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    bool read;
    bool write;
    bool receive;
} group_permission_t;

/** @brief Validate a pin against the HSM's pin
 *  Uses constant-time comparison to prevent timing attacks.
 *
 *  @param pin Requested pin to validate.
 *  @return True if the pin is valid. False if not.
 */
bool check_pin(unsigned char *pin);

/** @brief Ensure the HSM has the requested permission
 *
 *  @param group_id Group ID.
 *  @param perm Permission type.
 *  @return True if the HSM has the correct permission. False if not.
 */
bool validate_permission(uint16_t group_id, permission_enum_t perm);

/** @brief Check if a requesting HSM has receive permission for a group
 *
 *  @param requester_perms The requester's permission array
 *  @param group_id The group to check
 *  @return True if the requester has receive permission. False if not.
 */
bool validate_receive_permission(group_permission_t *requester_perms, uint16_t group_id);

/** @brief Check if a requesting HSM has interrogate (receive) permission for a group
 *
 *  @param requester_perms The requester's permission array
 *  @param group_id The group to check
 *  @return True if the requester has receive permission. False if not.
 */
bool validate_interrogate_permission(group_permission_t *requester_perms, uint16_t group_id);

/** @brief Compute a MAC over file data for integrity verification
 *
 *  @param data File contents
 *  @param len Length of data
 *  @param group_id Group ID of the file
 *  @param uuid UUID of the file
 *  @param mac_out Buffer of MAC_SIZE bytes for the output MAC
 */
void compute_file_mac(const uint8_t *data, size_t len, uint16_t group_id,
                      const uint8_t *uuid, uint8_t *mac_out);

/** @brief Verify a MAC over file data
 *
 *  @param data File contents
 *  @param len Length of data
 *  @param group_id Group ID of the file
 *  @param uuid UUID of the file
 *  @param expected_mac The MAC to verify against
 *  @return True if MAC matches. False if not.
 */
bool verify_file_mac(const uint8_t *data, size_t len, uint16_t group_id,
                     const uint8_t *uuid, const uint8_t *expected_mac);

#endif  // __SECURITY_H__
