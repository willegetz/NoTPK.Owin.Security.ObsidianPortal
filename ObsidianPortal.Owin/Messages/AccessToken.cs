namespace NoTPK.Owin.Security.ObsidianPortal.Messages
{
	public class AccessToken : RequestToken
	{
		public string UserId { get; set; }
		public string ScreenName { get; set; } 
	}
}