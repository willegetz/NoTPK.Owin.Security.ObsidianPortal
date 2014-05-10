# NoTPK.Owin.Security.ObsidianPortal
NoTPK.Owin.Security.ObsidianPortal is an [OWIN](http://owin.org/) authentication provider for [Obsidian Portal](http://www.obsidianportal.com)

## Installation via NuGet Package

Create an Obsidian Portal app to get your unique Client ID and Client Secret from: [https://www.obsidianportal.com/oauth/clients/new](https://www.obsidianportal.com/oauth/clients/new)

	Install-Package NoTPK.Owin.Security.ObsidianPortal

	Add the following to Startup.Auth.cs (VS2013) or AuthConfig.cs (VS2012):

            app.UseObsidianPortalAuthentication(
                clientId: "",
                clientSecret: "");


	Add the following to the AccountController.cs
	
	In the ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl) before the "await SignInAsync(user, isPersistent: false);"
	
	    await StoreAuthTokenClaims(user);


	Add the following method to the AccountController.cs
	
		private async Task StoreAuthTokenClaims(ApplicationUser user)
		{
			ClaimsIdentity claimsIdentity =
				await AuthenticationManager.GetExternalIdentityAsync(DefaultAuthenticationTypes.ExternalCookie);
			if (claimsIdentity != null)
			{
				var currentClaims = await UserManager.GetClaimsAsync(user.Id);
				var tokenClaims = claimsIdentity.Claims.Where(c => c.Type.StartsWith("urn:tokens"));
				foreach (var tokenClaim in tokenClaims)
				{
					if (!currentClaims.Contains(tokenClaim))
					{
						await UserManager.AddClaimAsync(user.Id, tokenClaim);
					}
				}
			}
		}



### Attribution

[This product includes software developed at: Microsoft Open Technologies, Inc.](https://github.com/johndpalm/Citrius.Owin.Security.Foursquare/blob/master/NOTICE.txt)

### License
[Apache v2 License](https://github.com/johndpalm/Citrius.Owin.Security.Foursquare/blob/master/LICENSE.txt)
