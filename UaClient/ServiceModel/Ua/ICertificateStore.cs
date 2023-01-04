// Copyright (c) Converter Systems LLC. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Parameters;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Workstation.ServiceModel.Ua
{
    /// <summary>
    /// The certificate store interface.
    /// </summary>
    public interface ICertificateStore
    {
        /// <summary>
        /// Gets the local certificate and private key.
        /// </summary>
        /// <param name="applicationDescription">The application description.</param>
        /// <param name="logger">The logger.</param>
        /// <returns>The local certificate and private key.</returns>
        Task<(X509Certificate2? Certificate, RsaKeyParameters? Key)> GetLocalCertificateAsync(ApplicationDescription applicationDescription, ILogger? logger, System.Threading.CancellationToken token);

        //Task<(X509Certificate2? Certificate, RsaKeyParameters? Key)> GetWindowsCertificateAsync(ILogger? logger, System.Threading.CancellationToken token);

        /// <summary>
        /// Validates the remote certificate.
        /// </summary>
        /// <param name="certificate">The remote certificate.</param>
        /// <param name="logger">The logger.</param>
        /// <returns>The validator result.</returns>
        Task<bool> ValidateRemoteCertificateAsync(X509Certificate2 certificate, ILogger? logger, CancellationToken token);
    }
}
