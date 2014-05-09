using Microsoft.Owin.Security.DataHandler.Serializer;

namespace NoTPK.Owin.Security.ObsidianPortal.Messages
{
	public class Serializers
	{
		public static IDataSerializer<RequestToken> RequestToken { get; set; }

		static Serializers()
		{
			Serializers.RequestToken = (IDataSerializer<RequestToken>)new RequestTokenSerializer();
		} 
	}
}