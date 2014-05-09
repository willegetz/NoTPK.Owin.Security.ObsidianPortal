using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using NoTPK.Owin.Security.ObsidianPortal.Messages;
using NoTPK.Owin.Security.ObsidianPortal.Providers;

namespace NoTPK.Owin.Security.ObsidianPortal
{
	public class ObsidianPortalAuthenticationOptions : AuthenticationOptions
	{
		public const string Scheme = "Obsidian Portal";

		public ObsidianPortalAuthenticationOptions() : base(Scheme)
		{
			Caption = Scheme;
			CallbackPath = new PathString("/signin-obsidianportal");
			AuthenticationMode = AuthenticationMode.Passive;
			BackchannelTimeout = TimeSpan.FromSeconds(60);
			Scope = new List<string>();
		}

		public string ConsumerKey { get; set; }
		
		public string ConsumerSecret { get; set; }
		
		public TimeSpan BackchannelTimeout { get; set; }
		
		public ICertificateValidator BackChannelCertificateValidator { get; set; }
		
		public HttpMessageHandler BackChannelHttpHandler { get; set; }

		public string Caption
		{
			get { return Description.Caption; }
			set { Description.Caption = value; }
		}
		
		public PathString CallbackPath { get; set; }

		public string SignInAsAuthenticationType { get; set; }
		
		public ISecureDataFormat<RequestToken> StateDataFormat { get; set; }
		
		public IObsidianPortalAuthenticationProvider Provider { get; set; }

		public IList<string> Scope { get; set; }
	}
}