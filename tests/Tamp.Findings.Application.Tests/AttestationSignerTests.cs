using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tamp.Findings.Application.Provenance;
using Xunit;

namespace Tamp.Findings.Application.Tests;

public class AttestationSignerTests
{
    [Fact]
    public void An_outbound_signature_verifies_against_its_own_public_key()
    {
        // The round-trip that proves the outbound signature is real: sign with
        // the deployment key, then verify with DsseVerifier using that key's
        // public half as the trust root — the same path inbound provenance takes.
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = AttestationSigner.FromPem(ec.ExportPkcs8PrivateKeyPem());
        Assert.True(signer.CanSign);
        Assert.NotNull(signer.PublicKeyPem);

        var document = Encoding.UTF8.GetBytes("{\"attestation\":\"ssdf\",\"score\":7.5}");
        var sig = signer.Sign(document);
        Assert.NotNull(sig);

        // Rebuild the DSSE envelope a verifier would check and verify it.
        var envelope = JsonSerializer.Serialize(new
        {
            payloadType = AttestationSigner.PayloadType,
            payload = Convert.ToBase64String(document),
            signatures = new[] { new { sig } },
        });
        var trust = ProvenanceTrustRoot.FromPems([signer.PublicKeyPem!]);
        var r = new DsseVerifier(trust).Verify(JsonDocument.Parse(envelope).RootElement);

        Assert.True(r.Verified);
    }

    [Fact]
    public void A_tampered_document_fails_verification_of_the_outbound_signature()
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = AttestationSigner.FromPem(ec.ExportPkcs8PrivateKeyPem());
        var sig = signer.Sign(Encoding.UTF8.GetBytes("original document"));

        var envelope = JsonSerializer.Serialize(new
        {
            payloadType = AttestationSigner.PayloadType,
            payload = Convert.ToBase64String(Encoding.UTF8.GetBytes("tampered document")),
            signatures = new[] { new { sig } },
        });
        var trust = ProvenanceTrustRoot.FromPems([signer.PublicKeyPem!]);

        Assert.False(new DsseVerifier(trust).Verify(JsonDocument.Parse(envelope).RootElement).Verified);
    }

    [Fact]
    public void With_no_key_configured_signing_is_unavailable()
    {
        var signer = AttestationSigner.FromPem(null);
        Assert.False(signer.CanSign);
        Assert.Null(signer.Sign(Encoding.UTF8.GetBytes("x")));
        Assert.Null(signer.KeyId);
    }
}
