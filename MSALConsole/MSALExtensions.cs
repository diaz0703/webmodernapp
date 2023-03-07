using Microsoft.Identity.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace MSALConsole
{
    public static class MSALExtensions
    {
        /// <summary>
        /// Implements acquiring a saml token from AzureAD using the OBO OAuth2 grant type.
        /// The acquired token is NOT cached.
        /// </summary>
        /// <param name="clientApp"></param>
        /// <param name="jwtToken"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        public static async Task<string> AcquireSamlFromJwtAsync(
            this IConfidentialClientApplication clientApp,
            string jwtToken,
            string scope
        )
        {
            using (var http = new HttpClient()) 
            {
                var reqParams = new Dictionary<string, string>
                {
                    {"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
                    {"assertion", jwtToken },
                    {"client_id" , clientApp.AppConfig.ClientId },
                    {"client_secret", HttpUtility.UrlEncode(clientApp.AppConfig.ClientSecret) },
                    {"scope", HttpUtility.UrlEncode(scope) },
                    {"requested_token_use", "on_behalf_of" },
                    {"requested_token_type", "urn:ietf:params:oauth:token-type:saml2" }
                };
                var body = reqParams.Aggregate("", (s, v1) => $"{s}&{v1.Key}={v1.Value}").Substring(1); // skip initial &
                var resp = await http.PostAsync($"{clientApp.Authority}/oauth2/v2.0/token", new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));
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
}
