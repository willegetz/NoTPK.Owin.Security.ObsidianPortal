using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace NoTPK.Owin.Security.ObsidianPortal.Providers
{
	public class ObsidianPortalReturnEndpointContext : ReturnEndpointContext
	{
		public ObsidianPortalReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
		{ }
	}
}