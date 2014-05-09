using System;
using System.Threading.Tasks;

namespace NoTPK.Owin.Security.ObsidianPortal.Providers
{
	public class ObsidianPortalAuthenticationProvider : IObsidianPortalAuthenticationProvider
	{
		public ObsidianPortalAuthenticationProvider()
		{
			OnAuthenticated = context => (Task)Task.FromResult<object>(null);
			OnReturnEndpoint = context => Task.FromResult<object>(null);
			OnApplyRedirect = context =>
				context.Response.Redirect(context.RedirectUri);
		}

		public Func<ObsidianPortalAuthenticatedContext, Task> OnAuthenticated { get; set; }
	
		public Func<ObsidianPortalReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

		public Action<ObsidianPortalApplyRedirectContext> OnApplyRedirect { get; set; }

		public Task Authenticated(ObsidianPortalAuthenticatedContext context)
		{
			return this.OnAuthenticated(context);
		}

		public Task ReturnEndpoint(ObsidianPortalReturnEndpointContext context)
		{
			return this.OnReturnEndpoint(context);
		}

		public void ApplyRedirect(ObsidianPortalApplyRedirectContext context)
		{
			this.OnApplyRedirect(context);
		}
	}
}