using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tamp.Findings.Application.Provenance;
using Xunit;

namespace Tamp.Findings.Application.Tests;

public class DsseVerifierTests
{
    private static (string Pem, ECDsa Key) NewEcKey()
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (ec.ExportSubjectPublicKeyInfoPem(), ec);
    }

    private static JsonElement Envelope(string payloadType, byte[] payload, ECDsa signer)
    {
        var pae = DsseVerifier.Pae(payloadType, payload);
        var sig = signer.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var json = JsonSerializer.Serialize(new
        {
            payloadType,
            payload = Convert.ToBase64String(payload),
            signatures = new[] { new { sig = Convert.ToBase64String(sig) } },
        });
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    [Fact]
    public void A_valid_signature_from_a_trusted_key_verifies()
    {
        var (pem, key) = NewEcKey();
        var trust = ProvenanceTrustRoot.FromPems([pem]);
        var env = Envelope("application/vnd.in-toto+json", Encoding.UTF8.GetBytes("{\"predicate\":1}"), key);

        var r = new DsseVerifier(trust).Verify(env);

        Assert.True(r.Verified);
        Assert.StartsWith("dsse:", r.Method);
    }

    [Fact]
    public void A_tampered_payload_does_not_verify()
    {
        var (pem, key) = NewEcKey();
        var trust = ProvenanceTrustRoot.FromPems([pem]);

        // Sign one payload, then swap it for another in the envelope.
        var pae = DsseVerifier.Pae("t", Encoding.UTF8.GetBytes("original"));
        var sig = key.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var json = JsonSerializer.Serialize(new
        {
            payloadType = "t",
            payload = Convert.ToBase64String(Encoding.UTF8.GetBytes("tampered")),
            signatures = new[] { new { sig = Convert.ToBase64String(sig) } },
        });

        Assert.False(new DsseVerifier(trust).Verify(JsonDocument.Parse(json).RootElement).Verified);
    }

    [Fact]
    public void A_signature_from_an_untrusted_key_does_not_verify()
    {
        var (_, signer) = NewEcKey();
        var (otherPem, _) = NewEcKey();
        var trust = ProvenanceTrustRoot.FromPems([otherPem]);
        var env = Envelope("t", Encoding.UTF8.GetBytes("x"), signer);

        Assert.False(new DsseVerifier(trust).Verify(env).Verified);
    }

    [Fact]
    public void With_no_trust_root_nothing_verifies()
    {
        var (_, signer) = NewEcKey();
        var env = Envelope("t", Encoding.UTF8.GetBytes("x"), signer);

        Assert.False(new DsseVerifier(ProvenanceTrustRoot.Empty).Verify(env).Verified);
    }
}
