using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace NoTPK.Owin.Security.ObsidianPortal.Providers
{
	public class ObsidianPortalAuthenticatedContext : BaseContext
	{
		public ObsidianPortalAuthenticatedContext(IOwinContext context, string userId, string screenName, string accessToken, string accessTokenSecret) : base(context)
		{
			UserId = userId;
			ScreenName = screenName;
			AccessToken = accessToken;
			AccessTokenSecret = accessTokenSecret;
		}

		public string UserId { get; set; }

		public string ScreenName { get; set; }

		public string AccessToken { get; set; }

		public string AccessTokenSecret { get; set; }

		public ClaimsIdentity Identity { get; set; }
		
		public AuthenticationProperties Properties { get; set; }
	}
}