using System.Security.Cryptography;

namespace Tamp.Findings.Application.Provenance;

// The deployment's OUTBOUND attestation signing key (TFND-160).
//
// Replaces the old "signature" that was just a typed-in name string: signing an
// attestation now produces a real cryptographic signature over the frozen
// document. The signature is taken over the DSSE PAE, so it is verifiable by the
// same machinery that checks INBOUND provenance (DsseVerifier) — a deployment
// can put its own public key in a trust root and round-trip its attestations.
//
// The private key is a deployment secret from config
// (Attestation:SigningKey / TAMP_FINDINGS_ATTESTATION_SIGNING_KEY, a PEM). No
// key => CanSign is false; the snapshot still records the human sign-off, but
// without a cryptographic signature, and the export says so.
public sealed class AttestationSigner
{
    // Media type bound into the PAE. Stable, because it is part of what a
    // verifier must reconstruct.
    public const string PayloadType = "application/vnd.tamp.findings.attestation+json";

    private readonly ECDsa? _ecdsa;
    private readonly RSA? _rsa;

    public bool CanSign => _ecdsa is not null || _rsa is not null;
    public string? KeyId { get; }
    public string? Algorithm { get; }
    public string? PublicKeyPem { get; }

    private AttestationSigner(ECDsa? ecdsa, RSA? rsa, string? keyId, string? algorithm, string? publicKeyPem)
    {
        _ecdsa = ecdsa;
        _rsa = rsa;
        KeyId = keyId;
        Algorithm = algorithm;
        PublicKeyPem = publicKeyPem;
    }

    public static AttestationSigner None { get; } = new(null, null, null, null, null);

    public static AttestationSigner FromPem(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem)) return None;

        try
        {
            var e = ECDsa.Create();
            e.ImportFromPem(pem);
            var spki = e.ExportSubjectPublicKeyInfo();
            return new AttestationSigner(e, null, Fingerprint(spki), "ECDSA-P256-SHA256-DER", e.ExportSubjectPublicKeyInfoPem());
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException) { }

        try
        {
            var r = RSA.Create();
            r.ImportFromPem(pem);
            var spki = r.ExportSubjectPublicKeyInfo();
            return new AttestationSigner(null, r, Fingerprint(spki), "RSA-PKCS1-SHA256", r.ExportSubjectPublicKeyInfoPem());
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException) { }

        return None;
    }

    // Base64 signature over the DSSE PAE of (PayloadType, payload), or null when
    // no key is configured.
    public string? Sign(byte[] payload)
    {
        var pae = DsseVerifier.Pae(PayloadType, payload);
        if (_ecdsa is not null)
            return Convert.ToBase64String(_ecdsa.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        if (_rsa is not null)
            return Convert.ToBase64String(_rsa.SignData(pae, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        return null;
    }

    // A stable key id: the SHA-256 of the SubjectPublicKeyInfo, hex. Lets an
    // export name the key without shipping it, and a verifier match it.
    private static string Fingerprint(byte[] spki) =>
        Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant();
}
