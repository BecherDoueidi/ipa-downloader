// ipabridge.h — C ABI of bridge/src/lib.rs + signing.rs. Keep in sync by hand.
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

// ---- Free Apple ID signing (bridge/src/signing.rs) ----

/// Store `value` under `key` in the Keychain. Return 0 on success.
typedef int32_t (*ipab_store_cb)(const char *key, const char *value);
/// Return a malloc'd (strdup) copy of the value for `key`, or NULL. The bridge frees it.
typedef char *(*ipab_retrieve_cb)(const char *key);
/// Show the 2FA prompt and block until answered. Return a malloc'd answer
/// (code, "d", "r", "p<id>") or NULL to abort. The bridge frees it.
typedef char *(*ipab_two_factor_cb)(const char *prompt, void *context);

/// Register Keychain callbacks once at startup, before any login.
void ipab_set_storage_callbacks(ipab_store_cb store, ipab_retrieve_cb retrieve);

/// Blocking. 0 = signed in. The password is used only for Apple's SRP login and not stored.
int32_t ipab_apple_login(const char *email, const char *password,
                         ipab_two_factor_cb two_factor, void *context,
                         char **out_message);

/// 1 if a developer session is open.
int32_t ipab_is_signed_in(void);

/// Drops the in-memory session.
void ipab_sign_out(void);

/// Blocking. Signs the IPA with the signed-in Apple ID and installs it. 0 = success.
/// Progress 0-50 signing, 50-100 installing.
int32_t ipab_sign_and_install(int32_t mode,
                              const uint8_t *data, size_t len,
                              const char *ip, uint16_t port,
                              const char *hostname,
                              const char *ipa_path,
                              int32_t allow_revoke,
                              ipab_progress_cb progress, void *progress_context,
                              char **out_message);

#endif
