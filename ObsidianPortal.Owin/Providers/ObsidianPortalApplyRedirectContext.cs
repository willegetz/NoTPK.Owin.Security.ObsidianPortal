using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace NoTPK.Owin.Security.ObsidianPortal.Providers
{
	public class ObsidianPortalApplyRedirectContext : BaseContext<ObsidianPortalAuthenticationOptions>
	{
		public ObsidianPortalApplyRedirectContext(IOwinContext context, ObsidianPortalAuthenticationOptions options, AuthenticationProperties properties, string redirectUri) : base(context, options)
		{
			RedirectUri = redirectUri;
			Properties = properties;
		}

		public string RedirectUri { get; set; }

		public AuthenticationProperties Properties { get; set; }
	}
}