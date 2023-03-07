using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

IConfiguration _config = builder.Configuration;

// Add services to the container.
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(_config.GetSection("AzureAd"))
    .EnableTokenAcquisitionToCallDownstreamApi().AddInMemoryTokenCaches();

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = options.DefaultPolicy;
});

builder.Services.AddControllersWithViews(options =>
{
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
});


builder.Services.AddRazorPages()
    .AddMicrosoftIdentityUI();

builder.Services.AddHttpClient("ApiProtegida", httpClient =>
{
    httpClient.BaseAddress = new Uri(_config.GetValue<string>("ApiAd:urlapi"));
    httpClient.DefaultRequestHeaders.Add(
        "x-header-app", "webdemo");
});
builder.Services.AddHttpClient("pidetoken", httpClient =>
{
    httpClient.BaseAddress = new Uri(_config.GetValue<string>("ApiAd:urltoken"));
    httpClient.DefaultRequestHeaders.Add("x-header-app", "webdemo");
});

builder.Services.AddHttpClient("apigraph", httpClient =>
{
    httpClient.BaseAddress = new Uri(_config.GetValue<string>("ApiAd:urlgraph"));
    httpClient.DefaultRequestHeaders.Add("x-header-app", "webdemo");
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();
app.MapControllers();

app.Run();
