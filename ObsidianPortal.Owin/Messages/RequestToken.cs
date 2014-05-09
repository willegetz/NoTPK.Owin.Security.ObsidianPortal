using Microsoft.Owin.Security;

namespace NoTPK.Owin.Security.ObsidianPortal.Messages
{
	public class RequestToken
	{
		public string Token { get; set; }

		public string TokenSecret { get; set; }

		public bool CallbackConfirmed { get; set; }

		public AuthenticationProperties Properties { get; set; } 
	}
}