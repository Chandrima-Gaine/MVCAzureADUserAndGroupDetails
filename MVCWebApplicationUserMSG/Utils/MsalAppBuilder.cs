using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Identity.Client;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MVCWebApplicationUserMSG.Utils
{
    public class MsalAppBuilder
    {
		/// <summary>
		/// Shared method to create an IConfidentialClientApplication from configuration and attach the application's token cache implementation
		/// </summary>
		/// <returns></returns>
		public static IConfidentialClientApplication BuildConfidentialClientApplication()
		{
			return BuildConfidentialClientApplication(ClaimsPrincipal.Current);
		}

		/// <summary>
		/// Shared method to create an IConfidentialClientApplication from configuration and attach the application's token cache implementation
		/// </summary>
		/// <param name="currentUser">The current ClaimsPrincipal</param>
		/// <returns></returns>
		public static IConfidentialClientApplication BuildConfidentialClientApplication(ClaimsPrincipal currentUser)
		{
			IConfidentialClientApplication clientapp = ConfidentialClientApplicationBuilder.Create(Globals.ClientId)
				  .WithClientSecret(Globals.ClientSecret)
				  .WithRedirectUri(Globals.RedirectUri)
				  .WithAuthority(new Uri(Globals.Authority))
				  .Build();

			// After the ConfidentialClientApplication is created, we overwrite its default UserTokenCache with our implementation
			MSALPerUserMemoryTokenCache userTokenCache = new MSALPerUserMemoryTokenCache(clientapp.UserTokenCache, currentUser ?? ClaimsPrincipal.Current);
			return clientapp;
		}

		/// <summary>
		/// Common method to remove the cached tokens for the currently signed in user
		/// </summary>
		/// <returns></returns>
		public static async Task ClearUserTokenCache()
		{
			IConfidentialClientApplication clientapp = ConfidentialClientApplicationBuilder.Create(Globals.ClientId)
				  .WithClientSecret(Globals.ClientSecret)
				  .WithRedirectUri(Globals.RedirectUri)
				  .WithAuthority(new Uri(Globals.Authority))
				  .Build();

			// We only clear the user's tokens.
			MSALPerUserMemoryTokenCache userTokenCache = new MSALPerUserMemoryTokenCache(clientapp.UserTokenCache);
			var userAccount = await clientapp.GetAccountAsync(ClaimsPrincipal.Current.GetMsalAccountId());

			//Remove the users from the MSAL's internal cache
			await clientapp.RemoveAsync(userAccount);
			userTokenCache.Clear();
		}
	}
}