using Microsoft.Owin.Security;
using NoTPK.Owin.Security.ObsidianPortal.Providers;

namespace NoTPK.Owin.Security.ObsidianPortal
{
	public class ObsidianPortalAuthenticationOptions : AuthenticationOptions
	{
		public const string Scheme = "Obsidian Portal";
		public ObsidianPortalAuthenticationOptions() : base(Scheme)
		{ }
		public string ConsumerKey { get; set; }
		public string ConsumerSecret { get; set; }

		public IObsidianPortalAuthenticationProvider Provider { get; set; }
	}
}