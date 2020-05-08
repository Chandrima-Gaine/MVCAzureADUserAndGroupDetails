using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Security.Claims;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Host.SystemWeb;
using MVCWebApplicationUserMSG.Utils;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;


namespace MVCWebApplicationUserMSG
{
    public partial  class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=316888

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions { });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    Authority = Globals.Authority,
                    ClientId = Globals.ClientId,
                    RedirectUri = Globals.RedirectUri,
                    PostLogoutRedirectUri = Globals.RedirectUri,
                    Scope = Globals.BasicSignInScopes, // a basic set of permissions for user sign in & profile access
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        // In a real application you would use ValidateIssuer = true for additional checks and security.
                        ValidateIssuer = false,
                        NameClaimType = "name",
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        SecurityTokenValidated = OnSecurityTokenValidated,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                        AuthenticationFailed = OnAuthenticationFailed,
                    },
                    // Handling SameSite cookie according to https://docs.microsoft.com/en-us/aspnet/samesite/owin-samesite
                    CookieManager = new SameSiteCookieManager(
                                     new SystemWebCookieManager())
                });
        }

        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            // Handle any unexpected errors during sign in
            context.OwinContext.Response.Redirect("/Error?message=" + context.Exception.Message);
            context.HandleResponse(); // Suppress the exception
            return Task.FromResult(0);
        }

        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification context)
        {
            /*
			 The `MSALPerUserMemoryTokenCache` is created and hooked in the `UserTokenCache` used by `IConfidentialClientApplication`.
			 At this point, if you inspect `ClaimsPrinciple.Current` you will notice that the Identity is still unauthenticated and it has no claims,
			 but `MSALPerUserMemoryTokenCache` needs the claims to work properly. Because of this sync problem, we are using the constructor that
			 receives `ClaimsPrincipal` as argument and we are getting the claims from the object `AuthorizationCodeReceivedNotification context`.
			 This object contains the property `AuthenticationTicket.Identity`, which is a `ClaimsIdentity`, created from the token received from 
			 Azure AD and has a full set of claims.
			 */
            IConfidentialClientApplication confidentialClient = MsalAppBuilder.BuildConfidentialClientApplication(new ClaimsPrincipal(context.AuthenticationTicket.Identity));

            // Upon successful sign in, get & cache a token using MSAL
            AuthenticationResult result = await confidentialClient.AcquireTokenByAuthorizationCode(new[] { "user.readbasic.all" }, context.Code).ExecuteAsync();
        }

        private Task OnSecurityTokenValidated(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            // Verify the user signing in is a business user, not a consumer user.
            string[] issuer = context.AuthenticationTicket.Identity.FindFirst(Globals.IssuerClaim).Value.Split('/');
            string tenantId = issuer[(issuer.Length - 2)];
            if (tenantId == Globals.ConsumerTenantId)
            {
                throw new SecurityTokenValidationException("Consumer accounts are not supported for the Group Manager App.  Please log in with your work account.");
            }

            return Task.FromResult(0);
        }
    }
}
