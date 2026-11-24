// ipabridge.h — C ABI of bridge/src/lib.rs. Keep in sync by hand (4 functions).
#ifndef IPABRIDGE_H
#define IPABRIDGE_H

#include <stddef.h>
#include <stdint.h>

#define IPAB_MODE_LOCKDOWN 0
#define IPAB_MODE_RPPAIRING 1

#define IPAB_PAIRING_INVALID -1
#define IPAB_PAIRING_LOCKDOWN 1
#define IPAB_PAIRING_RPPAIRING 2

typedef void (*ipab_progress_cb)(uint64_t percent, void *context);

/// Static string, do not free.
const char *ipab_version(void);

/// Frees any string returned through an `out_message` parameter.
void ipab_free_string(char *s);

/// Returns IPAB_PAIRING_LOCKDOWN, IPAB_PAIRING_RPPAIRING or IPAB_PAIRING_INVALID.
int32_t ipab_inspect_pairing(const uint8_t *data, size_t len, char **out_message);

/// Blocking. 0 = success. `port` is only used in RPPairing mode.
int32_t ipab_test_connection(int32_t mode,
                             const uint8_t *data, size_t len,
                             const char *ip, uint16_t port,
                             const char *hostname,
                             char **out_message);

/// Blocking. 0 = success. The IPA must already be signed for this device.
int32_t ipab_install_ipa(int32_t mode,
                         const uint8_t *data, size_t len,
                         const char *ip, uint16_t port,
                         const char *hostname,
                         const char *ipa_path,
                         ipab_progress_cb progress, void *progress_context,
                         char **out_message);

#endif
