// Copyright (c) Converter Systems LLC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Workstation.ServiceModel.Ua
{
    /// <summary>
    /// A certificate store.
    /// </summary>
    public class WindowsCertificateStore : ICertificateStore
    {
        private readonly string _thumbprint;
        private readonly string _keyThumbprint;
        private readonly StoreName _storeName;
        private readonly StoreLocation _storeLocation;
        private readonly X509CertificateParser _certParser = new X509CertificateParser();
        private readonly SecureRandom _rng = new SecureRandom();

        /// <summary>
        /// Initializes a new instance of the <see cref="DirectoryStore"/> class.
        /// </summary>
        /// <param name="storeName">The path to the local pki directory.</param>
        /// <param name="storeLocation">Set true to accept all remote certificates.</param>
        /// <param name="thumbprint">Set true to create a local certificate and private key, if the files do not exist.</param>
        public WindowsCertificateStore(StoreName storeName, StoreLocation storeLocation, string thumbprint, string keyThumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint) || string.IsNullOrEmpty(keyThumbprint))
            {
                throw new ArgumentNullException(nameof(thumbprint));
            }

            _storeName = storeName;
            _storeLocation = storeLocation;
            _thumbprint = thumbprint;
            _keyThumbprint = keyThumbprint;
        }

        /// <inheritdoc/>
        public async Task<(X509Certificate? Certificate, RsaKeyParameters? Key)> GetLocalCertificateAsync(ApplicationDescription applicationDescription, ILogger? logger = null, CancellationToken token = default)
        {
            var crt = default(X509Certificate);
            X509Store store = new X509Store(_storeName, _storeLocation);

            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection cerCollection = store.Certificates
                .Find(X509FindType.FindByTemplateName, _thumbprint, true);

            store.Close();

            if (cerCollection.Count > 0)
            {
                X509CertificateParser parser = new X509CertificateParser();

                crt = parser.ReadCertificate(cerCollection.OfType<X509Certificate2>().OrderBy(c => c.NotBefore).LastOrDefault().RawData);
            }
            else
            {
                throw new CryptographicException("Certificate Not found");
            }

            var key = default(RsaKeyParameters);

            IX509Store ownCertStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(cerCollection));

            if (crt != null)
            {
                // If certificate found, verify alt-name, and retrieve private key.
                var asn1OctetString = crt.GetExtensionValue(X509Extensions.SubjectAlternativeName);
                if (asn1OctetString != null)
                {
                    var asn1Object = X509ExtensionUtilities.FromExtensionValue(asn1OctetString);
                    GeneralNames gns = GeneralNames.GetInstance(asn1Object);
                    if (gns.GetNames().Any(n => n.TagNo == GeneralName.UniformResourceIdentifier && n.Name.ToString() == applicationUri))
                    {
                        var ki = new FileInfo(Path.Combine(_pkiPath, "own", "private", $"{crt.SerialNumber}.key"));
                        if (ki.Exists)
                        {
                            using (var keyStream = new StreamReader(ki.OpenRead()))
                            {
                                var keyReader = new PemReader(keyStream);
                                var keyPair = keyReader.ReadObject() as AsymmetricCipherKeyPair;
                                if (keyPair != null)
                                {
                                    key = keyPair.Private as RsaKeyParameters;
                                }
                            }
                        }
                    }
                }
            }

            // If certificate and key are found, return to caller.
            if (crt != null && key != null)
            {
                logger?.LogTrace($"Found certificate with thumbprint '{_thumbprint}'.");

                return (crt, key);
            }

            //if (!CreateLocalCertificateIfNotExist)
            //{
            return (null, null);
            //}

            //// Create new certificate
            //var subjectDN = new X509Name(subjectName);

            //// Create a keypair.
            //var kp = await Task.Run<AsymmetricCipherKeyPair>(() =>
            //{
            //    RsaKeyPairGenerator kg = new RsaKeyPairGenerator();
            //    kg.Init(new KeyGenerationParameters(_rng, 2048));
            //    return kg.GenerateKeyPair();
            //});

            //key = kp.Private as RsaPrivateCrtKeyParameters;

            //// Create a certificate.
            //X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
            //var subjectSN = BigInteger.ProbablePrime(120, _rng);
            //cg.SetSerialNumber(subjectSN);
            //cg.SetSubjectDN(subjectDN);
            //cg.SetIssuerDN(subjectDN);
            //cg.SetNotBefore(DateTime.Now.Date.ToUniversalTime());
            //cg.SetNotAfter(DateTime.Now.Date.ToUniversalTime().AddYears(25));
            //cg.SetPublicKey(kp.Public);

            //cg.AddExtension(
            //    X509Extensions.BasicConstraints.Id,
            //    true,
            //    new BasicConstraints(false));

            //cg.AddExtension(
            //    X509Extensions.SubjectKeyIdentifier.Id,
            //    false,
            //    new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public)));

            //cg.AddExtension(
            //    X509Extensions.AuthorityKeyIdentifier.Id,
            //    false,
            //    new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public), new GeneralNames(new GeneralName(subjectDN)), subjectSN));

            //cg.AddExtension(
            //    X509Extensions.SubjectAlternativeName,
            //    false,
            //    new GeneralNames(new[] { new GeneralName(GeneralName.UniformResourceIdentifier, applicationUri), new GeneralName(GeneralName.DnsName, hostName) }));

            //cg.AddExtension(
            //    X509Extensions.KeyUsage,
            //    true,
            //    new KeyUsage(KeyUsage.DataEncipherment | KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyCertSign | KeyUsage.KeyEncipherment));

            //cg.AddExtension(
            //    X509Extensions.ExtendedKeyUsage,
            //    true,
            //    new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth, KeyPurposeID.IdKPServerAuth));

            //crt = cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", key, _rng));

            //logger?.LogTrace($"Created certificate with subject alt name '{applicationUri}'.");

            //var keyInfo = new FileInfo(Path.Combine(_pkiPath, "own", "private", $"{crt.SerialNumber}.key"));
            //if (!keyInfo.Directory.Exists)
            //{
            //    Directory.CreateDirectory(keyInfo.DirectoryName);
            //}
            //else if (keyInfo.Exists)
            //{
            //    keyInfo.Delete();
            //}

            //using (var keystream = new StreamWriter(keyInfo.OpenWrite()))
            //{
            //    var pemwriter = new PemWriter(keystream);
            //    pemwriter.WriteObject(key);
            //}

            //var crtInfo = new FileInfo(Path.Combine(_pkiPath, "own", "certs", $"{crt.SerialNumber}.crt"));
            //if (!crtInfo.Directory.Exists)
            //{
            //    Directory.CreateDirectory(crtInfo.DirectoryName);
            //}
            //else if (crtInfo.Exists)
            //{
            //    crtInfo.Delete();
            //}

            //using (var crtstream = new StreamWriter(crtInfo.OpenWrite()))
            //{
            //    var pemwriter = new PemWriter(crtstream);
            //    pemwriter.WriteObject(crt);
            //}

            //return (crt, key);
        }

        /// <inheritdoc/>
        public Task<bool> ValidateRemoteCertificateAsync(X509Certificate target, ILogger? logger = null, CancellationToken token = default)
        {
            //if (AcceptAllRemoteCertificates)
            //{
            //    return Task.FromResult(true);
            //}
            
            if (target == null)
            {
                throw new ArgumentNullException(nameof(target));
            }

            if (!target.IsValidNow)
            {
                logger?.LogError($"Error validatingRemoteCertificate. Certificate is expired or not yet valid.");
                return Task.FromResult(false);
            }

            var trustedCerts = new Org.BouncyCastle.Utilities.Collections.HashSet();

            //foreach (var info in trustedCertsInfo.EnumerateFiles())
            //{
            //    using (var crtStream = info.OpenRead())
            //    {
            //        var crt = _certParser.ReadCertificate(crtStream);
            //        if (crt != null)
            //        {
            //            trustedCerts.Add(crt);
            //        }
            //    }
            //}

            var intermediateCerts = new Org.BouncyCastle.Utilities.Collections.HashSet();

            //foreach (var info in intermediateCertsInfo.EnumerateFiles())
            //{
            //    using (var crtStream = info.OpenRead())
            //    {
            //        var crt = _certParser.ReadCertificate(crtStream);
            //        if (crt != null)
            //        {
            //            intermediateCerts.Add(crt);
            //        }
            //    }
            //}
            
            if (IsSelfSigned(target))
            {
                // Create the selector that specifies the starting certificate
                var selector = new X509CertStoreSelector()
                {
                    Certificate = target
                };
                IX509Store trustedCertStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(trustedCerts));
                if (trustedCertStore.GetMatches(selector).Count > 0)
                {
                    return Task.FromResult(true);
                }

                logger?.LogError($"Error validatingRemoteCertificate.");
                return Task.FromResult(false);
            }

            try
            {
                var res = VerifyCertificate(target, trustedCerts, intermediateCerts);
            }
            catch (Exception ex)
            {
                logger?.LogError($"Error validatingRemoteCertificate. {ex.Message}");
                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }

        private static PkixCertPathBuilderResult VerifyCertificate(X509Certificate target, Org.BouncyCastle.Utilities.Collections.HashSet trustedRootCerts, Org.BouncyCastle.Utilities.Collections.HashSet intermediateCerts)
        {
            intermediateCerts.Add(target);

            // Create the selector that specifies the starting certificate
            var selector = new X509CertStoreSelector()
            {
                Certificate = target
            };

            // Create the trust anchors (set of root CA certificates)
            var trustAnchors = new Org.BouncyCastle.Utilities.Collections.HashSet();
            foreach (X509Certificate? trustedRootCert in trustedRootCerts)
            {
                trustAnchors.Add(new TrustAnchor(trustedRootCert, null));
            }

            PkixBuilderParameters pkixParams = new PkixBuilderParameters(trustAnchors, selector)
            {

                // Disable CRL checks (this is done manually as additional step)
                IsRevocationEnabled = false
            };

            // Specify a list of intermediate certificates
            IX509Store intermediateCertStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(intermediateCerts));
            pkixParams.AddStore(intermediateCertStore);

            // Build and verify the certification chain
            PkixCertPathBuilder builder = new PkixCertPathBuilder();
            PkixCertPathBuilderResult result = builder.Build(pkixParams);
            return result;
        }

        /// <summary>
        /// Checks whether given <see cref="X509Certificate"/> is self-signed.
        /// </summary>
        /// <param name="cert">an <see cref="X509Certificate"/>.</param>
        /// <returns>True, if self signed.</returns>
        private static bool IsSelfSigned(X509Certificate cert)
        {
            try
            {
                // Try to verify certificate signature with its own public key
                var key = cert.GetPublicKey();
                cert.Verify(key);
                return true;
            }
            catch (SignatureException)
            {
                // Invalid signature --> not self-signed
                return false;
            }
            catch (InvalidKeyException)
            {
                // Invalid key --> not self-signed
                return false;
            }
        }
    }
}