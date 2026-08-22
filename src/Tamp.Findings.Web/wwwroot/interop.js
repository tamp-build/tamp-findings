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
  }
};
