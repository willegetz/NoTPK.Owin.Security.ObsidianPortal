using NoTPK.Owin.Security.ObsidianPortal;
using NoTPK.Owin.Security.ObsidianPortal.Providers;
using System;
using System.Security.Claims;

namespace Owin
{
	public static class ObsidianPortalAuthenticationExtensions
	{
		public static IAppBuilder UseObsidianPortalAuthentication(IAppBuilder app, ObsidianPortalAuthenticationOptions options)
		{
			if (app == null)
			{
				throw new ArgumentException("app");
			}

			if (options == null)
			{
				throw new ArgumentException("options");
			}

			app.Use(typeof(ObsidianPortalAuthenticationMiddleWare), app, options);
			return app;
		}

		public static IAppBuilder UseObsidianPortalAuthentication(this IAppBuilder app, string appId, string appSecret)
		{
			var options = new ObsidianPortalAuthenticationOptions()
			{
				ConsumerKey = appId,
				ConsumerSecret = appSecret,
				Provider = new ObsidianPortalAuthenticationProvider()
				{
					OnAuthenticated = async context =>
					{
						context.Identity.AddClaim(new Claim("urn:tokens:obsidianportal:accesstoken", context.AccessToken));
						context.Identity.AddClaim(new Claim("urn:tokens:obsidianportal:accesstokensecret", context.AccessTokenSecret));
					}
				}
			};

			return UseObsidianPortalAuthentication(app, options);
		} 
	}
}