using commoncourse;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Text.Json;

namespace webmodernapp.Controllers
{
    [Authorize]
    public class AccesoController : Controller
    {
        private IHttpClientFactory _http;
        private IConfiguration _config;
        private ITokenAcquisition _tokenAcquisition;

        public AccesoController(IHttpClientFactory http, IConfiguration config,
            ITokenAcquisition tokenad)
        {
            _http = http;
            _config = config;
            _tokenAcquisition = tokenad;
        }
        
        
        public async Task< IActionResult> LlamadaApi()
        {
            IEnumerable<claseclima> ListaElementos= null;
            var scope = _config.GetValue<string>("AzureAd:Scopes");
            var accessToken = await _tokenAcquisition.GetAccessTokenForUserAsync(new[] { scope });
            var httpClient = _http.CreateClient("ApiProtegida");
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue ("Bearer" ,accessToken);
            var httpResponseMessage = await httpClient.GetAsync("WeatherForecast");
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                var contentStream =
                    await httpResponseMessage.Content.ReadAsStringAsync();
                ListaElementos = JsonSerializer.Deserialize <IEnumerable<claseclima>>(contentStream);
            }
            return View(ListaElementos);
        }


        public IActionResult MuestraToken()
        {
            Dictionary<string,string> _losclaims = new Dictionary<string,string>();
            foreach (var token in User.Claims)
            { 
                _losclaims.Add(token.Type, token.Value);    
            }
            return View(_losclaims);
        }


        public async Task<IActionResult> MuestraTokenAccess()
        {
            
            var scope = _config.GetValue<string>("AzureAd:Scopes");
            var accessToken = await _tokenAcquisition.GetAccessTokenForUserAsync(new[] { scope });

            var stream = accessToken;
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadToken(stream);
            var tokenS = jsonToken as JwtSecurityToken;



            Dictionary<string, string> _losclaims = new Dictionary<string, string>();
            foreach (var token in  tokenS.Claims)
            {
                if(! _losclaims.Keys.Contains(token.Type) )
                  _losclaims.Add(token.Type, token.Value);
            }
            return View(_losclaims);
        }

    }
}
