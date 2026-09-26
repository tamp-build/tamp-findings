using System.Text;
using System.Text.Json;

namespace Tamp.Findings.Application.Provenance;

public sealed record ProvenanceVerification(bool Verified, string? Method);

// Verifies a DSSE envelope's signature against the trust root (TFND-159).
//
// A DSSE envelope is { payloadType, payload (base64), signatures: [{ sig
// (base64), keyid? }] }. Verification is over the DSSE Pre-Authentication
// Encoding (PAE) of (payloadType, payload). Crucially, we do NOT trust the
// predicateType/payloadType string — presence is not proof. Only a signature
// over the PAE by a key in the trust root counts, which is the whole point of
// TFND-159: the old code flipped SSDF PS.2.1 to "Yes" on the mere presence of
// a self-uploaded blob.
public sealed class DsseVerifier
{
    private readonly ProvenanceTrustRoot _trust;
    public DsseVerifier(ProvenanceTrustRoot trust) => _trust = trust;

    public static ProvenanceVerification Unverified { get; } = new(false, null);

    public ProvenanceVerification Verify(JsonElement envelope)
    {
        // No trust root → we cannot verify anything, and must not pretend to.
        if (!_trust.HasKeys) return Unverified;
        if (envelope.ValueKind != JsonValueKind.Object) return Unverified;

        if (!TryGetString(envelope, "payloadType", out var payloadType)) return Unverified;
        if (!TryGetString(envelope, "payload", out var payloadB64)) return Unverified;
        if (!envelope.TryGetProperty("signatures", out var sigs) || sigs.ValueKind != JsonValueKind.Array) return Unverified;

        byte[] payload;
        try { payload = Convert.FromBase64String(payloadB64); }
        catch (FormatException) { return Unverified; }

        var pae = Pae(payloadType, payload);

        foreach (var s in sigs.EnumerateArray())
        {
            if (!TryGetString(s, "sig", out var sigB64)) continue;
            byte[] sig;
            try { sig = Convert.FromBase64String(sigB64); }
            catch (FormatException) { continue; }

            foreach (var key in _trust.Keys)
                if (key.Verify(pae, sig))
                    return new ProvenanceVerification(true, $"dsse:{key.Id}");
        }

        return Unverified;
    }

    // DSSE Pre-Authentication Encoding (in-toto/DSSE spec):
    //   "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
    // where LEN is the ASCII decimal of the byte length and the type/payload
    // are their raw bytes.
    internal static byte[] Pae(string payloadType, byte[] payload)
    {
        var type = Encoding.UTF8.GetBytes(payloadType);
        using var ms = new MemoryStream();
        void Ascii(string s) { var b = Encoding.ASCII.GetBytes(s); ms.Write(b, 0, b.Length); }

        Ascii("DSSEv1 ");
        Ascii(type.Length.ToString()); Ascii(" ");
        ms.Write(type, 0, type.Length); Ascii(" ");
        Ascii(payload.Length.ToString()); Ascii(" ");
        ms.Write(payload, 0, payload.Length);
        return ms.ToArray();
    }

    private static bool TryGetString(JsonElement el, string name, out string value)
    {
        value = "";
        if (el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String)
        {
            value = p.GetString() ?? "";
            return value.Length > 0;
        }
        return false;
    }
}
