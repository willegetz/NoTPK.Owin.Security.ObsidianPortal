using System.Security.Claims;

namespace NoTPK.Owin.Security.ObsidianPortal.Providers
{
	public class ObsidianPortalAuthenticatedContext
	{
		public string AccessToken { get; set; }

		public string AccessTokenSecret { get; set; }

		public ClaimsIdentity Identity { get; set; }
	}
}