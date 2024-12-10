using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertLeakTest
{
    internal static class Program
    {
        private const string DefaultTempFileLocation = @"D:\local\Temp";
        static object _storeLock = new();
        static X509Certificate2 _cert;

        static void Main(string[] args)
        {
            try
            {
                var useStore = args.Length == 0;
                FileCount("Initial");
                var bytes = SelfSignedCertificateHelper.CreateSelfSignCertificatePfx($"CN=deletable-{Guid.NewGuid()}", DateTime.UtcNow, DateTime.UtcNow.AddDays(1));
                FileCount("After CreateSelfSignCertificatePfx");

                X509Certificate2 cert;
                if (useStore)
                {
                    cert = FindOrAddCertInUserStore(bytes);
                    FileCount($"After FindOrAddCertInUserStore");
                }
                else
                {
                    cert = CertFromBytesInCache(bytes);
                    FileCount($"After CertFromBytesInCache");
                }

                TestPrivateKey(cert);

                if (useStore)
                {
                    DeleteCertFromUserStore();
                    FileCount("After DeleteCertFromUserStore");
                }
                else
                {
                    ClearCache();
                    FileCount("After ClearCache");
                }

                TestPrivateKey(cert);
                cert.Dispose();
            }
            catch (Exception ex)
            {
                TraceLine(ex);
            }

            FileCount("Before GC Collect");
            GC.Collect();
            GC.WaitForPendingFinalizers();
            FileCount("After GC Collect");
        }

        public static void TestPrivateKey(X509Certificate2 cert)
        {
            var rawData = Guid.NewGuid().ToByteArray();
            var sig = cert.GetRSAPrivateKey().SignData(rawData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            cert.GetRSAPublicKey().VerifyData(rawData, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var cipher = cert.GetRSAPublicKey().Encrypt(rawData, RSAEncryptionPadding.OaepSHA256);
            var result = cert.GetRSAPrivateKey().Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
            if (rawData.Length != result.Length || !rawData.SequenceEqual(result))
            {
                throw new Exception("TestPrivateKey Encrypt failed");
            }

            TraceLine($"TestPrivateKey passed {cert.Subject}");
        }

        static ConcurrentDictionary<string, X509Certificate2> _certCache = new();
        public static X509Certificate2 CertFromBytesInCache(byte[] bytes)
        {
            using var sha256 = SHA256.Create();
            var key = Convert.ToBase64String(sha256.ComputeHash(bytes));
            var cert = _certCache.GetOrAdd(key, k =>
            {
                // regardless of persist or not -- it is created file in RSA but disposed along with cert or GC
                return CreateX509FromFile(bytes, X509KeyStorageFlags.UserKeySet);
            });

            // dup and the caller is responsible to dispose the object
            // use X509Certificate2(cert) for each cert lifetime dependency, last dispose + GC will remove RSA file
            // use X509Certificate2(handle) - master cert dispose will remove key and clone will nto work.
            return new X509Certificate2(cert);
        }

        public static void ClearCache()
        {
            foreach (var cert in _certCache.Values)
            {
                // no need since we don't persist
                // cert.DeleteKeyContainer();
                cert.Dispose();
            }
            _certCache.Clear();
        }

        public static void DeleteKeyContainer(this X509Certificate2 cert)
        {
            // remove key container from C:\Users\suwatch\AppData\Roaming\Microsoft\Crypto\RSA
            if (cert.PrivateKey is RSACryptoServiceProvider rsa)
            {
                TraceLine($"Cert RSACryptoServiceProvider container file removed {cert.Subject}, keyContainerName: {rsa.CspKeyContainerInfo.KeyContainerName}, uniqueKeyContainerName: {rsa.CspKeyContainerInfo.UniqueKeyContainerName}");
                rsa.PersistKeyInCsp = false;
                rsa.Clear();
            }
            else if (cert.PrivateKey is RSACng rsaCng)
            {
                //TraceLine($"Cert RSACng container file removed {cert.Subject}, {rsaCng.Key.C.CspKeyContainerInfo.UniqueKeyContainerName}");
                // rsa.PersistKeyInCsp = false;
                rsaCng.Clear();
            }
            else
            {
                TraceLine($"Cert PrivateKey {cert.PrivateKey.GetType()} is not supported");
            }
        }

        // C:\Users\suwatch\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates
        public static void FileCount(string title)
        {
            TraceLine($"===== {title} {nameof(FileCount)} =====");
            var userProfileFolder = Environment.GetEnvironmentVariable("USERPROFILE");
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_DEPLOYMENT_ID")))
            {
                userProfileFolder = Environment.ExpandEnvironmentVariables(@"%SystemDrive%\users\%WEBSITE_DEPLOYMENT_ID%");
            }

            // dir /a /s /b %SystemDrive%\users\%WEBSITE_DEPLOYMENT_ID%\AppData\Roaming\Microsoft\Crypto\RSA
            var folder = Path.Combine(userProfileFolder, Environment.ExpandEnvironmentVariables(@"AppData\Roaming\Microsoft\Crypto\RSA"));
            TraceLine($"{folder}: {Directory.EnumerateFiles(folder, "*.*", SearchOption.AllDirectories).Count()}");

            folder = Path.Combine(userProfileFolder, Environment.ExpandEnvironmentVariables(@"AppData\Roaming\Microsoft\SystemCertificates\My\Certificates"));
            TraceLine($"{folder}: {Directory.EnumerateFiles(folder, "*.*", SearchOption.AllDirectories).Count()}");

            folder = Path.Combine(userProfileFolder, Environment.ExpandEnvironmentVariables(@"AppData\Roaming\Microsoft\SystemCertificates\My\Keys"));
            TraceLine($"{folder}: {Directory.EnumerateFiles(folder, "*.*", SearchOption.AllDirectories).Count()}");

            GetDiskFreeSpaceEx(userProfileFolder, out var freeBytesAvailable, out var totalNumberOfBytes, out var totalNumberOfFreeBytes);
            TraceLine($"Free: {freeBytesAvailable / 1_000}KB, Total: {totalNumberOfBytes / 1_000}KB, Free: {totalNumberOfFreeBytes / 1_000}KB");
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetDiskFreeSpaceEx(string lpDirectoryName,
            out ulong lpFreeBytesAvailable,
            out ulong lpTotalNumberOfBytes,
            out ulong lpTotalNumberOfFreeBytes);

        public static void DeleteCertFromUserStore()
        {
            // Using the subject name for the cert, try to find the most recent version of the cert if its already installed in the cert store
            lock (_storeLock)
            {
                using X509Store rwStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                rwStore.Open(OpenFlags.ReadWrite);

                var certificates = rwStore.Certificates;
                TraceLine($"Total Cert = {certificates.Count}");
                var max = 1000;
                foreach (var cert in certificates)
                {
                    if (cert.Subject.Contains("deletable-"))
                    {
                        rwStore.Remove(cert);
                        TraceLine($"Cert removed {cert.Subject}, {cert.Thumbprint}");

                        // remove key container from C:\Users\suwatch\AppData\Roaming\Microsoft\Crypto\RSA since using X509KeyStorageFlags.PersistKeySet
                        cert.DeleteKeyContainer();

                        if (max-- < 0)
                        {
                            break;
                        }
                    }
                }

                rwStore.Close();
            }
        }

        public static X509Certificate2 FindOrAddCertInUserStore(byte[] privateKeyBytes)
        {
            // Using the subject name for the cert, try to find the most recent version of the cert if its already installed in the cert store
            using (X509Certificate2 tempCert = CreateX509FromFile(privateKeyBytes, X509KeyStorageFlags.EphemeralKeySet))
            {
                lock (_storeLock)
                {
                    using X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly);

                    // Ok to lookup by thumbprint as the expected thumbprint will rotate as the certificate (represented by input bytes) rotates. This is just a cache
                    var certificates = store.Certificates;
                    var total = certificates.Count;
                    var matchingCerts = certificates.Find(X509FindType.FindByThumbprint, tempCert.Thumbprint, validOnly: true);
                    TraceLine($"Total Cert = {certificates.Count}, Matching Certs: {matchingCerts.Count}");
                    if (matchingCerts.Count > 0)
                    {
                        return matchingCerts[0]; // Return the first matching cert we find
                    }
                }
            }

            // if we fail to find the cert in the user store, try to install it
            // X509KeyStorageFlags.PersistKeySet add key to %SystemDrive%\users\%WEBSITE_DEPLOYMENT_ID%\AppData\Roaming\Microsoft\Crypto\RSA
            // X509KeyStorageFlags.PersistKeySet is needed when adding cert to X509Store
            var newCertToAdd = CreateX509FromFile(privateKeyBytes, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);

            lock (_storeLock)
            {
                using X509Store rwStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                // Add to Store add key to %SystemDrive%\users\%WEBSITE_DEPLOYMENT_ID%\AppData\Roaming\Microsoft\SystemCertificates\My\Keys
                // Add to Store add cert to %SystemDrive%\users\%WEBSITE_DEPLOYMENT_ID%\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates
                rwStore.Open(OpenFlags.ReadWrite);
                rwStore.Add(newCertToAdd);
                rwStore.Close();
                TraceLine($"Cert added {newCertToAdd.Subject}, {newCertToAdd.Thumbprint}, {((RSACryptoServiceProvider)newCertToAdd.PrivateKey).CspKeyContainerInfo.UniqueKeyContainerName}");
            }

            return newCertToAdd;
        }

        public static X509Certificate2 CreateX509FromFile(byte[] privateKeyBytes, X509KeyStorageFlags flags)
        {
            var tempFolderEnvVar = Environment.GetEnvironmentVariable("TEMP");
            var tempFolderLocation = !string.IsNullOrEmpty(tempFolderEnvVar) ? tempFolderEnvVar : DefaultTempFileLocation;
            var folderLocation = Path.Combine(tempFolderLocation, "kvhelper");
            Directory.CreateDirectory(folderLocation); // ensure the directory exists

            var file = Path.Combine(folderLocation, "swa-" + Guid.NewGuid());
            X509Certificate2 cert = null;
            try
            {
                File.WriteAllBytes(file, privateKeyBytes);
                cert = new X509Certificate2(file, string.Empty, flags);
            }
            finally
            {
                File.Delete(file);
            }

            return cert;
        }

        public static void TraceLine(object message)
        {
            Console.WriteLine($"{DateTime.UtcNow:s} {message}");
        }
    }
}
