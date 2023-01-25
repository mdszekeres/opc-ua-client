using FluentAssertions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Workstation.ServiceModel.Ua;
using Xunit;

namespace Workstation.UaClient.UnitTests
{
    public class WindowsCertificateStoreTests
    {
        // These will need to be filled in with your own test values to test correctly.
        #region Test Certificates

        private WindowsCertificate testClientWindowsCertificate = new WindowsCertificate
        {
            StoreLocation = StoreLocation.LocalMachine,
            StoreName = StoreName.My,
            thumbprints = new List<string>()
            {
                ""
            }
        };

        private WindowsCertificate testTrustedWindowsCertificate = new WindowsCertificate
        {
            StoreLocation = StoreLocation.LocalMachine,
            StoreName = StoreName.My,
            thumbprints = new List<string>()
            {
                "",
                ""
            }
        };

        private WindowsCertificate testIssuerWindowsCertificate = new WindowsCertificate
        {
            StoreLocation = StoreLocation.LocalMachine,
            StoreName = StoreName.My,
            thumbprints = new List<string>()
            {
                ""
            }
        };

        #endregion

        [InlineData(null)]
        [Theory]
        public void ConstructorNull(WindowsCertificate testCertificate)
        {
            testCertificate.Invoking(testCert =>
                new WindowsCertificateStore(testCert, testTrustedWindowsCertificate, testIssuerWindowsCertificate))
                .Should().Throw<NullReferenceException>();
        }

        [Fact]
        public void ConstructorMissingThumbprint()
        {
            WindowsCertificate testCertificate = new WindowsCertificate();

            testCertificate.Invoking(testCert =>
                    new WindowsCertificateStore(testCert, testTrustedWindowsCertificate, testIssuerWindowsCertificate))
                .Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void ConstructorClientCertOverload()
        {
            WindowsCertificate overloadedClientCert = new WindowsCertificate()
            {
                StoreLocation = StoreLocation.LocalMachine,
                StoreName = StoreName.My,
                thumbprints = new List<string>()
                {
                    "1234",
                    "431"
                }
            };

            overloadedClientCert.Invoking(testCert =>
                    new WindowsCertificateStore(testCert, testTrustedWindowsCertificate, testIssuerWindowsCertificate))
                .Should().Throw<ArgumentException>();
        }

        [Fact]
        public async Task LoadCertificate()
        {
            var store = new WindowsCertificateStore(testClientWindowsCertificate, testTrustedWindowsCertificate, testIssuerWindowsCertificate);

            var app = new ApplicationDescription
            {
                ApplicationUri = "urn:hostname:appname",
            };

            var (cert1, key1) = await store.GetLocalCertificateAsync(app);
            var (cert2, key2) = await store.GetLocalCertificateAsync(app);

            cert1
                .Should().Be(cert2);

            key1
                .Should().Be(key2);
        }

        //[Fact]
        //public async Task ValidateCertificateAcceptAll()
        //{
        //    var store = new WindowsCertificateStore(testClientWindowsCertificate, testTrustedWindowsCertificate, testIssuerWindowsCertificate);

        //    var ret = await store.ValidateRemoteCertificateAsync(null);

        //    ret
        //        .Should().BeTrue();
        //}

        [Fact]
        public async Task ValidateCertificateNull()
        {
            var store = new WindowsCertificateStore(testClientWindowsCertificate, testTrustedWindowsCertificate, testIssuerWindowsCertificate);

            await store.Invoking(s => s.ValidateRemoteCertificateAsync(null))
                    .Should().ThrowAsync<ArgumentNullException>();
        }

        [Fact]
        public async Task ValidateCertificateExisting()
        {
            // certificate with private key will be your server client
            // and your clients server certificate
            var storeServer = new WindowsCertificateStore(testClientWindowsCertificate, testTrustedWindowsCertificate, testIssuerWindowsCertificate);
            var storeClient = new WindowsCertificateStore(testClientWindowsCertificate, testClientWindowsCertificate, testIssuerWindowsCertificate);

            var server = new ApplicationDescription
            {
                ApplicationUri = "http://hostname/server",
            };

            var (cert, _) = await storeServer.GetLocalCertificateAsync(server);

            // hence it should be accepted
            var ret = await storeClient.ValidateRemoteCertificateAsync(cert);
            ret
                .Should().BeTrue();
        }
    }
}
