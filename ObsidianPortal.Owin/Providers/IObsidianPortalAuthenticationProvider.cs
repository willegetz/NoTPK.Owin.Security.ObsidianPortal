using System.Threading.Tasks;

namespace NoTPK.Owin.Security.ObsidianPortal.Providers
{
	public interface IObsidianPortalAuthenticationProvider
	{
		Task Authenticated(ObsidianPortalAuthenticatedContext context);
		Task ReturnEndpoint(ObsidianPortalReturnEndpointContext context);
		void ApplyRedirect(ObsidianPortalApplyRedirectContext context);
	}
}