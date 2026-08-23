// Minimal JS interop surface. Kept deliberately small: everything the design
// needs is achievable server-side except clipboard access, which has no
// server-side equivalent.
window.tampFindings = {
  // Returns a rejected promise when the clipboard is unavailable (insecure
  // origin, denied permission) so the caller can leave its label unchanged
  // rather than claiming a copy that did not happen.
  copyText: async function (text) {
    if (!navigator.clipboard) throw new Error('clipboard unavailable');
    await navigator.clipboard.writeText(text);
  },

  // View preferences (density, deltas). localStorage throws outright in some
  // configurations — a private window, blocked site data — rather than merely
  // returning null, so both accessors swallow. A lost preference is a
  // convenience not working; a thrown one would break the render.
  get: function (key) {
    try { return window.localStorage.getItem(key); } catch { return null; }
  },
  set: function (key, value) {
    try { window.localStorage.setItem(key, value); } catch { /* ignore */ }
  }

};

// Hand a generated file to the browser (TFND-101).
//
// The bytes arrive base64 because the document is already built server-side
// and fetching it over a second request could rebuild it — producing a file
// that disagrees with what the reader just looked at.
//
// A blob URL rather than a data: URL: a full attestation PDF runs past the
// length some browsers will accept in an address, and a truncated download is
// worse than a failed one.
window.tampDownload = function (fileName, mediaType, base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

  const url = URL.createObjectURL(new Blob([bytes], { type: mediaType }));
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Revoke on the next turn, not immediately: some browsers have not yet
  // started reading the blob when click() returns.
  setTimeout(() => URL.revokeObjectURL(url), 10000);
};
