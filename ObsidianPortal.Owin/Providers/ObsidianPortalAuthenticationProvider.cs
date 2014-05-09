using System;
using System.Threading.Tasks;

namespace NoTPK.Owin.Security.ObsidianPortal.Providers
{
	public class ObsidianPortalAuthenticationProvider : IObsidianPortalAuthenticationProvider
	{
		public ObsidianPortalAuthenticationProvider()
		{
			OnAuthenticated = context => (Task)Task.FromResult<object>(null);
		}

		public Func<ObsidianPortalAuthenticatedContext, Task> OnAuthenticated { get; set; }
		public Task Authenticated(ObsidianPortalAuthenticatedContext context)
		{
			return this.OnAuthenticated(context);
		}

		public Task ReturnEndpoint(ObsidianPortalReturnEndpointContext context)
		{
			throw new System.NotImplementedException();
		}

		public void ApplyRedirect(ObsidianPortalApplyRedirectContext context)
		{
			throw new System.NotImplementedException();
		}
	}
}