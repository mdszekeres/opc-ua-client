
// Copyright (c) Converter Systems LLC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
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
using PemReader = Org.BouncyCastle.Utilities.IO.Pem.PemReader;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Workstation.ServiceModel.Ua
{
    public class WindowsCertificate
    {
        public StoreName StoreName { get; set; }
        public StoreLocation StoreLocation { get; set; }
        public List<string> thumbprints { get; set; }
    }

    /// <summary>
    /// A certificate store.
    /// </summary>
    public class WindowsCertificateStore : ICertificateStore
    {
        private readonly WindowsCertificate _clientCertificate;
        private readonly WindowsCertificate _trustedCertificate;
        private readonly WindowsCertificate _issuerCertificate;
        private readonly X509CertificateParser _certParser = new X509CertificateParser();
        private readonly SecureRandom _rng = new SecureRandom();

        /// <summary>
        /// Initializes a new instance of the <see cref="DirectoryStore"/> class.
        /// </summary>
        /// <param name="clientCertificate">Client certificate object that should hold only one thumb print.</param>
        /// <param name="trustedCertificate">Set true to accept all remote certificates.</param>
        /// <param name="issuerCertificate">Set true to create a local certificate and private key, if the files do not exist.</param>
        public WindowsCertificateStore(WindowsCertificate clientCertificate, WindowsCertificate trustedCertificate, WindowsCertificate issuerCertificate)
        {
            if (clientCertificate is null)
            {
                throw new NullReferenceException();
            }
            if (!clientCertificate.thumbprints.Any())
            {
                throw new ArgumentNullException(nameof(clientCertificate.thumbprints));
            }

            if (clientCertificate.thumbprints.Count > 1)
            {
                throw new ArgumentException("client Certification list is larger than expected.");
            }

            _clientCertificate = clientCertificate;
            _trustedCertificate = trustedCertificate;
            _issuerCertificate = issuerCertificate;
        }

        /// <inheritdoc/>
        public async Task<(X509Certificate? Certificate, RsaKeyParameters? Key)> GetLocalCertificateAsync(ApplicationDescription applicationDescription, ILogger? logger = null, CancellationToken token = default)
        {
            var crt = default(X509Certificate2);
            X509Store store = new X509Store(_clientCertificate.StoreName, _clientCertificate.StoreLocation);
            
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection cerCollection = store.Certificates
                .Find(X509FindType.FindByThumbprint, _clientCertificate.thumbprints.First().ToUpper(), false);

            store.Close();

            if (cerCollection.Count > 0)
            {
                // This takes the latest certificate found if there are mutliples that are not expired and match the thumb print.
                crt = cerCollection.OfType<X509Certificate2>().OrderBy(c => c.NotBefore).LastOrDefault();
            }
            else
            {
                throw new CryptographicException("Certificate Not found");
            }

            var key = default(RsaKeyParameters);

            if (crt != null)
            {
                if (crt.HasPrivateKey)
                {
                    var keyParameter = TransformRSAPrivateKey(crt);
                    key = keyParameter as RsaKeyParameters;
                }
            }

            // If certificate and key are found, return to caller.
            if (crt != null && key != null)
            {
                logger?.LogTrace($"Found certificate with thumbprint '{_clientCertificate.thumbprints.First()}'.");

                // need to convert to x509Certificate
                var rtnCrt = _certParser.ReadCertificate(crt.RawData);

                return (rtnCrt, key);
            }

            return (null, null);
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
            X509Store trustedStore = new X509Store(_trustedCertificate.StoreName, _trustedCertificate.StoreLocation);
            trustedStore.Open(OpenFlags.ReadOnly);

            foreach (var thumbThumbprint in _trustedCertificate.thumbprints)
            {
                X509Certificate2Collection trustedCerCollection = trustedStore.Certificates
                    .Find(X509FindType.FindByThumbprint, thumbThumbprint, false);

                // Loads found certs into the trusted list
                foreach (var trustedCert in trustedCerCollection)
                {
                    var trustedCrt = _certParser.ReadCertificate(trustedCert.RawData);
                    trustedCerts.Add(trustedCrt);
                }
            }

            trustedStore.Close();

            var intermediateCerts = new Org.BouncyCastle.Utilities.Collections.HashSet();
            X509Store issuerStore = new X509Store(_issuerCertificate.StoreName, _issuerCertificate.StoreLocation);
            issuerStore.Open(OpenFlags.ReadOnly);

            foreach (var thumbThumbprint in _issuerCertificate.thumbprints)
            {
                X509Certificate2Collection issuerCerCollection = issuerStore.Certificates
                    .Find(X509FindType.FindByThumbprint, thumbThumbprint, false);

                // Loads found certs into the intermediate list
                foreach (var issuerCert in issuerCerCollection)
                {
                    var issuerCrt = _certParser.ReadCertificate(issuerCert.RawData);
                    intermediateCerts.Add(issuerCrt);
                }
            }

            issuerStore.Close();

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

        /// <summary>
        /// Rebuilds the private key into an AsymmetricKeyParameter
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        private static AsymmetricKeyParameter TransformRSAPrivateKey(
            X509Certificate2 certificate)
        {
            var privateKey = certificate.GetRSAPrivateKey();

            RSAParameters parameters = privateKey.ExportParameters(true);

            return new RsaPrivateCrtKeyParameters(
                new BigInteger(1, parameters.Modulus),
                new BigInteger(1, parameters.Exponent),
                new BigInteger(1, parameters.D),
                new BigInteger(1, parameters.P),
                new BigInteger(1, parameters.Q),
                new BigInteger(1, parameters.DP),
                new BigInteger(1, parameters.DQ),
                new BigInteger(1, parameters.InverseQ));
        }
    }
}