/**
 * Saving media out of Vardum, and deleting what Vardum saved (b69).
 *
 * Android: no broad photo/video permission (Google Play's photo and video
 * permissions policy; a messenger doesn't qualify). "Save to…" opens the
 * system folder picker (Storage Access Framework). expo-file-system takes a
 * persistable grant on the chosen folder, so the duress wipe and
 * Nothing-at-Rest can still delete the files Vardum saved there, with no
 * prompt and no gallery permission. Saved files are tracked by their
 * content:// URI.
 *
 * iOS is unchanged: Photos via expo-media-library with full access (b92 F14),
 * tracked by asset id.
 */
import { Platform } from 'react-native';
import * as FileSystem from 'expo-file-system';
import * as MediaLibrary from 'expo-media-library';

const SAF = FileSystem.StorageAccessFramework;

/** True for an Android "Save to…" file (a SAF content:// URI), not a Photos asset id. */
export const isSafUri = (id: string): boolean => id.startsWith('content://');

/** Android only: "Save to…" uses the folder picker instead of gallery access. */
export const usesFolderPicker = (): boolean => Platform.OS === 'android';

/**
 * Android: ask the user for a folder, then write the file there.
 * Returns the saved file's content:// URI, or null if the user cancelled.
 */
export async function saveToChosenFolder(b64: string, fileName: string, mime: string): Promise<string | null> {
  const perm = await SAF.requestDirectoryPermissionsAsync();
  if (!perm.granted) return null;
  // createFileAsync adds the extension from the mime type itself
  const base = fileName.replace(/\.[^./]+$/, '');
  const uri = await SAF.createFileAsync(perm.directoryUri, base, mime);
  await SAF.writeAsStringAsync(uri, b64, { encoding: FileSystem.EncodingType.Base64 });
  return uri;
}

/**
 * Delete media Vardum saved (the veil_saved_media list). Android files are
 * removed through the folder grant; Photos assets only on iOS (on Android the
 * media permissions are not declared, and expo-media-library rejects without
 * them). Tries every item, then throws the first error so callers can count it.
 */
export async function deleteSavedMedia(ids: string[]): Promise<void> {
  let firstError: unknown = null;
  for (const uri of ids.filter(isSafUri)) {
    try { await FileSystem.deleteAsync(uri, { idempotent: true }); } catch (e) { firstError ??= e; }
  }
  const assets = ids.filter((id) => !isSafUri(id));
  if (assets.length && Platform.OS !== 'android') {
    try {
      const perm = await MediaLibrary.getPermissionsAsync();
      if (perm.granted) await MediaLibrary.deleteAssetsAsync(assets);
    } catch (e) { firstError ??= e; }
  }
  if (firstError) throw firstError;
}
