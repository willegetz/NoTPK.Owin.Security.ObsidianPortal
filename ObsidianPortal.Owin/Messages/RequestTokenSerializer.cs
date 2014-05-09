using System;
using System.IO;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Serializer;

namespace NoTPK.Owin.Security.ObsidianPortal.Messages
{
	public class RequestTokenSerializer : IDataSerializer<RequestToken>
	{
		private const int FormatVersion = 1;

		public virtual byte[] Serialize(RequestToken model)
		{
			using (var memory = new MemoryStream())
			{
				using (var writer = new BinaryWriter(memory))
				{
					Write(writer, model);
					writer.Flush();
					return memory.ToArray();
				}
			}
		}

		public virtual RequestToken Deserialize(byte[] data)
		{
			using (var memory = new MemoryStream(data))
			{
				using (var reader = new BinaryReader(memory))
				{
					return Read(reader);
				}
			}
		}

		public static void Write(BinaryWriter writer, RequestToken token)
		{
			if (writer == null)
			{
				throw new ArgumentNullException("writer");
			}
			if (token == null)
			{
				throw new ArgumentNullException("token");
			}

			writer.Write(FormatVersion);
			writer.Write(token.Token);
			writer.Write(token.TokenSecret);
			writer.Write(token.CallbackConfirmed);
			PropertiesSerializer.Write(writer, token.Properties);
		}

		public static RequestToken Read(BinaryReader reader)
		{
			if (reader == null)
			{
				throw new ArgumentNullException("reader");
			}

			if (reader.ReadInt32() != FormatVersion)
			{
				return null;
			}

			string token = reader.ReadString();
			string tokenSecret = reader.ReadString();
			bool callbackConfirmed = reader.ReadBoolean();
			AuthenticationProperties properties = PropertiesSerializer.Read(reader);
			if (properties == null)
			{
				return null;
			}

			return new RequestToken { Token = token, TokenSecret = tokenSecret, CallbackConfirmed = callbackConfirmed, Properties = properties };
		}
	}
}