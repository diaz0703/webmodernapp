using Microsoft.Identity.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Xml.Linq;


// https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Client-Applications

namespace MSALConsole
{
    class Program
    {
        // Registered app in AAD
        // Note /common - means any org or MSA (default)
        //      /organizations - means orgs only
        static string _authority = "https://login.microsoftonline.com/0a56b010-8d4f-4deb-ba4f-006cb7af65a1";

        static string[] _apiGraphScopes = new string[] { "https://graph.microsoft.com/User.Read" };

        static string _publicClientId = "41834265-ede1-4f95-8b3a-58b2bac26702";

        static string _apiAppId = "8b810fff-ca3e-4df0-8aac-634172aa8350";
        static string _apiSecret = "6xC8Q~pN7izOszsVO8m~KBK3ruxIWzK~seyOMdB2";
        static string _apiResourceUri = "https://ocag547outlook.onmicrosoft.com/MyWebApi";
        static string[] _apiResourceScopes = { $"{_apiResourceUri}/reader" };

        static string _confidentialClientId = "41834265-ede1-4f95-8b3a-58b2bac26702";
        static string _confidentialClientSecret = "6xC8Q~pN7izOszsVO8m~KBK3ruxIWzK~seyOMdB2";

        static string _userName = "simon@ocag547outlook.onmicrosoft.com";

        static void Main(string[] args)
        {
            var p = new Program();
            p.UseMSAL().Wait();
        }

        private async Task UseMSAL()
        {
            var pClient = PublicClientApplicationBuilder
                .Create(_publicClientId)
                .WithAuthority(_authority)
                //.WithRedirectUri("https://login.microsoftonline.com/common/oauth2/nativeclient")
                .WithDefaultRedirectUri()
                .Build();
            IConfidentialClientApplication cClient;
            var exit = false;
            do
            {
                try
                {
                    ShowMenu();
                    var key = Console.ReadKey();
                    switch (key.KeyChar)
                    {
                        case '1':
                            Console.WriteLine("Auth Code Grant - public client");
                            ShowTokens(await pClient.AcquireTokenInteractive(_apiResourceScopes).ExecuteAsync());
                            //ShowTokens(await pClient.AcquireTokenInteractive(new string[] { _apiResourceId + "/creator" }).ExecuteAsync());
                            break;
                        case 'S':
                            Console.WriteLine("Auth Code Grant - public client");
                            ShowTokens(await pClient.AcquireTokenSilent(_apiResourceScopes, (await pClient.GetAccountsAsync()).First()).ExecuteAsync());
                            //ShowTokens(await pClient.AcquireTokenInteractive(new string[] { _apiResourceId + "/creator" }).ExecuteAsync());
                            break;
                        case '2':
                            Console.WriteLine("Client credentials (symetric)");
                            cClient = ConfidentialClientApplicationBuilder
                                .Create(_confidentialClientId)
                                .WithClientSecret(_confidentialClientSecret)
                                .WithAuthority(_authority)
                                .Build();
                            ShowTokens(await cClient.AcquireTokenForClient(new string[] { $"{_apiResourceUri}/.default" }).ExecuteAsync());
                            break;
                        case '3':
                            Console.WriteLine("Client credentials (X509)");
                            cClient = ConfidentialClientApplicationBuilder
                                .Create(_confidentialClientId)
                                .WithCertificate(new X509Certificate2("./cert.pfx", "password"))
                                .WithTenantId("modernauthn.onmicrosoft.com")
                                .Build();
                            ShowTokens(await cClient.AcquireTokenForClient(new string[] { $"{_apiResourceUri}/.default" }).ExecuteAsync());
                            break;
                        case '4':
                            Console.WriteLine("Resource owner password (public).");
                            var securePwd = GetPassword(_userName);
                            ShowTokens(await pClient.AcquireTokenByUsernamePassword(
                                _apiResourceScopes,
                                _userName,
                                securePwd).ExecuteAsync());
                            break;
                        case '5':
                            Console.WriteLine("Not supported");
                            break;
                        case '6':
                            Console.WriteLine("On-behalf of (JWT)");
                            var apiTokens = await pClient.AcquireTokenInteractive(_apiResourceScopes).ExecuteAsync();
                            // Now API exchanges that token for another one to MS Graph
                            cClient = ConfidentialClientApplicationBuilder
                                .Create(_apiAppId)
                                .WithClientSecret(_apiSecret)
                                .WithAuthority(_authority)
                                .Build();
                            var reqParams = cClient.AcquireTokenOnBehalfOf(_apiGraphScopes,
                                                            new UserAssertion(apiTokens.AccessToken, "urn:ietf:params:oauth:grant-type:jwt-bearer"));
                            ShowTokens(await reqParams.ExecuteAsync());
                            break;
                        case '7':
                            Console.WriteLine("On-behalf of (return SAML)");
                            apiTokens = await pClient.AcquireTokenInteractive(_apiResourceScopes).ExecuteAsync();
                            // Now API exchanges that token for another one to MS Graph
                            cClient = ConfidentialClientApplicationBuilder
                                .Create(_apiAppId)
                                .WithClientSecret(_apiSecret)
                                .WithAuthority(_authority)
                                .Build();
                            var saml = await cClient.AcquireSamlFromJwtAsync(
                                apiTokens.AccessToken,
                                "api://demoapi2/user_impersonation"
                            );
                            Console.WriteLine("Base64 encoded SAML: {0}", saml);
                            break;
                        case '9':
                            Console.WriteLine("Device Code - public client");
                            ShowTokens(await pClient.AcquireTokenWithDeviceCode
                                (
                                    _apiResourceScopes,
                                    result =>
                                    {
                                        Console.WriteLine(result.Message);
                                        return Task.FromResult(0);
                                    }).ExecuteAsync());
                            break;
                        case 'W':
                            Console.WriteLine("Resource Owner using WIA (public)");
                            ShowTokens(await pClient.AcquireTokenByIntegratedWindowsAuth(_apiResourceScopes).ExecuteAsync());
                            break;
                        case 'q':
                        case 'Q':
                            exit = true;
                            break;
                        default:
                            Console.WriteLine("Invalid entry.");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            } while (!exit);
        }
        private static void ShowMenu()
        {
            Console.WriteLine("Enter acquire token method:");
            Console.WriteLine("1. Auth Code Grant (public client).");
            Console.WriteLine("2. Client credentials - symetric.");
            Console.WriteLine("3. Client Credentials - X509.");
            Console.WriteLine("4. Resource owner.");
            Console.WriteLine("6. On-behalf of user (return JWT).");
            Console.WriteLine("7. On-behalf of user (retun SAML).");
            Console.WriteLine("9. Device code (public client).");
            Console.WriteLine("W. Resource owner using WIA (public client).");
            Console.WriteLine("Q. Quit");
        }
        private static void ShowTokens(AuthenticationResult result)
        {
            try
            {
                foreach (var p in result.GetType().GetProperties())
                {
                    Console.WriteLine($"{p.Name}: {p.GetValue(result)}");
                }
            }
            catch (Exception)
            {

            }
            Console.WriteLine();
        }

        private static SecureString GetPassword(string userName)
        {
            // NOTE: Resource owner, just like SecureString should not be used at all: https://github.com/dotnet/platform-compat/blob/master/docs/DE0001.md
            // Here is why. :)
            Console.Write($"Enter password for {userName}: ");
            var pwd = Console.ReadLine();
            var str = new SecureString();
            pwd.Select(c =>
            {
                str.AppendChar(c);
                return c;
            }).ToList();
            return str;
        }
        private static X509Certificate2 ReadCertificateFromStore(string thumbPrint)
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            var certCollection = store.Certificates;

            // Find unexpired certificates.
            var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

            // From the collection of unexpired certificates, find the ones with the correct thumbprint.
            var signingCert = currentCerts.Find(X509FindType.FindByThumbprint, thumbPrint, false);

            // Return the first certificate in the collection, has the right name and is current.
            var cert = signingCert.OfType<X509Certificate2>().OrderByDescending(c => c.NotBefore).FirstOrDefault();
            store.Close();
            return cert;
        }
        /// <summary>
        /// Returns Base64 encoded SAML token using the AAD OBO exchange of a JWT token.
        /// </summary>
        /// <param name="auth"></param>
        /// <param name="jwtToken"></param>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <param name="resourceId"></param>
        /// <returns></returns>
        private static async Task<string> AcquireSamlFromJWTAsync(
            string authority,
            string jwtToken,
            string clientId,
            string clientSecret,
            string scope
            )
        {

            var http = new HttpClient();
            var reqParams = new Dictionary<string, string>
            {
                {"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
                {"assertion", jwtToken },
                {"client_id" , clientId },
                {"client_secret", HttpUtility.UrlEncode(clientSecret) },
                {"scope", HttpUtility.UrlEncode(scope) },
                {"requested_token_use", "on_behalf_of" },
                {"requested_token_type", "urn:ietf:params:oauth:token-type:saml2" }
            };
            var body = reqParams.Aggregate("", (s, v1) => $"{s}&{v1.Key}={v1.Value}").Substring(1); // skip initial &
            var resp = await http.PostAsync($"{authority}/oauth2/v2.0/token", new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));
            if (resp.IsSuccessStatusCode)
            {
                var authResult = await resp.Content.ReadAsStringAsync();
                var saml = (string)JObject.Parse(authResult)["access_token"];
                return saml;
            }
            else
                throw new Exception(resp.ReasonPhrase);
        }
    }
}
