using System.Security.Cryptography;

namespace Tamp.Findings.Application.Provenance;

// The public keys this deployment trusts to have signed inbound provenance
// (TFND-159 / ADR 0004). Loaded from deployment CONFIG — like the enforcement
// lock, a verification trust root is a platform concern, not a per-request one.
//
// Empty = no trust root configured, so nothing verifies and SSDF PS.2.1 stays
// "Partial (unverified)" rather than the old, dishonest "Yes" on mere presence.
public sealed class ProvenanceTrustRoot
{
    public IReadOnlyList<TrustedKey> Keys { get; }
    public bool HasKeys => Keys.Count > 0;

    public ProvenanceTrustRoot(IEnumerable<TrustedKey> keys) => Keys = keys.ToList();

    public static ProvenanceTrustRoot Empty { get; } = new(Array.Empty<TrustedKey>());

    // Build from PEM public-key strings; any that don't parse as an ECDSA or
    // RSA public key are skipped (a malformed key must not silently become a
    // trust root of zero that verifies nothing without saying so — callers log
    // the loaded count).
    public static ProvenanceTrustRoot FromPems(IEnumerable<string> pems)
    {
        var keys = new List<TrustedKey>();
        var i = 0;
        foreach (var pem in pems)
        {
            i++;
            if (string.IsNullOrWhiteSpace(pem)) continue;
            if (TrustedKey.TryLoad($"key{i}", pem) is { } key) keys.Add(key);
        }
        return new ProvenanceTrustRoot(keys);
    }
}

// One trusted verification key. Wraps an ECDSA or RSA public key; Ed25519 is
// not yet supported by the BCL and is a follow-up.
public sealed class TrustedKey
{
    public string Id { get; }
    private readonly ECDsa? _ecdsa;
    private readonly RSA? _rsa;

    private TrustedKey(string id, ECDsa? ecdsa, RSA? rsa)
    {
        Id = id;
        _ecdsa = ecdsa;
        _rsa = rsa;
    }

    public static TrustedKey? TryLoad(string id, string pem)
    {
        try { var e = ECDsa.Create(); e.ImportFromPem(pem); return new TrustedKey(id, e, null); }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException) { }

        try { var r = RSA.Create(); r.ImportFromPem(pem); return new TrustedKey(id, null, r); }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException) { }

        return null;
    }

    // Verify a signature over `data`. ECDSA signatures are ASN.1/DER encoded,
    // as cosign and the DSSE tooling produce them; RSA uses PKCS#1 v1.5. Both
    // over SHA-256, the DSSE/sigstore default.
    public bool Verify(byte[] data, byte[] signature)
    {
        try
        {
            if (_ecdsa is not null)
                return _ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (_rsa is not null)
                return _rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException) { }
        return false;
    }
}
