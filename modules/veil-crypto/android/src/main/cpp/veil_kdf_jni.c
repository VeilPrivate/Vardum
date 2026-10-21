/*
 * JNI entry point for Pbkdf2Sha256.nativeDerive (Kotlin). The whole
 * derivation runs in one native call — no per-iteration JNI crossings.
 * Called from the expo AsyncFunction's background thread, never the UI thread.
 */
#include <jni.h>
#include "pbkdf2_sha256.h"

/* Largest derived key one call returns. The app asks for 16..64 bytes
   (bounded in VeilCryptoModule.pbkdf2Sha256); the tests go up to 130. */
#define VEIL_KDF_MAX_OUT 1024

static void wipe_bytes(jbyte *p, jsize n) {
  volatile jbyte *v = (volatile jbyte *)p;
  while (n-- > 0) *v++ = 0;
}

/* Returns 0 on success, negative on bad arguments / JNI failure. */
JNIEXPORT jint JNICALL
Java_expo_modules_veilcrypto_Pbkdf2Sha256_nativeDerive(JNIEnv *env, jclass cls,
                                                       jbyteArray password, jbyteArray salt,
                                                       jint iterations, jbyteArray out) {
  (void)cls;
  if (password == NULL || salt == NULL || out == NULL || iterations <= 0) return -1;
  jsize pw_len = (*env)->GetArrayLength(env, password);
  jsize salt_len = (*env)->GetArrayLength(env, salt);
  jsize out_len = (*env)->GetArrayLength(env, out);
  if (out_len <= 0 || out_len > VEIL_KDF_MAX_OUT) return -1;

  jboolean pw_copy = JNI_FALSE;
  jbyte *pw = (*env)->GetByteArrayElements(env, password, &pw_copy);
  if (pw == NULL) return -2;
  jbyte *s = (*env)->GetByteArrayElements(env, salt, NULL);
  if (s == NULL) {
    if (pw_copy) wipe_bytes(pw, pw_len);
    (*env)->ReleaseByteArrayElements(env, password, pw, JNI_ABORT);
    return -2;
  }
  /* RV-29: derive into our own stack buffer and copy it in with
     SetByteArrayRegion, so no VM-made copy of the derived key is ever freed
     unwiped (ReleaseByteArrayElements(out, 0) used to do exactly that).
     (No malloc: the host test DLL is built without a C runtime.) */
  jbyte o[VEIL_KDF_MAX_OUT];

  veil_pbkdf2_hmac_sha256((const uint8_t *)pw, (size_t)pw_len,
                          (const uint8_t *)s, (size_t)salt_len,
                          (uint32_t)iterations,
                          (uint8_t *)o, (size_t)out_len);

  (*env)->SetByteArrayRegion(env, out, 0, out_len, o);
  wipe_bytes(o, out_len);
  (*env)->ReleaseByteArrayElements(env, salt, s, JNI_ABORT);
  /* A VM-made copy of the password is ours to clear before it is freed;
     the Kotlin caller clears its own array. */
  if (pw_copy) wipe_bytes(pw, pw_len);
  (*env)->ReleaseByteArrayElements(env, password, pw, JNI_ABORT);
  return (*env)->ExceptionCheck(env) ? -2 : 0;
}
