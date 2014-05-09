using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using NoTPK.Owin.Security.ObsidianPortal.Messages;
using NoTPK.Owin.Security.ObsidianPortal.Providers;
using Owin;

namespace NoTPK.Owin.Security.ObsidianPortal
{
	public class ObsidianPortalAuthenticationMiddleWare : AuthenticationMiddleware<ObsidianPortalAuthenticationOptions>
	{
		private readonly ILogger _logger;
		private readonly HttpClient _httpClient;
		public ObsidianPortalAuthenticationMiddleWare(OwinMiddleware next, IAppBuilder app, ObsidianPortalAuthenticationOptions options)
			: base(next, options)
		{
			if (string.IsNullOrWhiteSpace(Options.ConsumerKey))
				throw new ArgumentException("The app id must be provided");

			if (string.IsNullOrWhiteSpace(Options.ConsumerSecret))
				throw new ArgumentException("the app secret must be provided");

			_logger = app.CreateLogger<ObsidianPortalAuthenticationMiddleWare>();

			if (Options.Provider == null)
				Options.Provider = new ObsidianPortalAuthenticationProvider();

			if (Options.StateDataFormat == null)
			{
				IDataProtector dataProtector = app.CreateDataProtector(typeof(ObsidianPortalAuthenticationMiddleWare).FullName,
					Options.AuthenticationType, "v1");
				Options.StateDataFormat = new SecureDataFormat<RequestToken>(Serializers.RequestToken, dataProtector, TextEncodings.Base64);
			}

			if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
				Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

			_httpClient = new HttpClient(ResolveHttpMessageHandler(Options));
			_httpClient.Timeout = Options.BackchannelTimeout;
			_httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10;
			_httpClient.DefaultRequestHeaders.Accept.ParseAdd("*/*");
			_httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft Owin Obsidian Portal middleware");
			_httpClient.DefaultRequestHeaders.ExpectContinue = false;
		}

		protected override AuthenticationHandler<ObsidianPortalAuthenticationOptions> CreateHandler()
		{
			return new ObsidianPortalAuthenticationHandler(_httpClient, _logger);
		}

		private HttpMessageHandler ResolveHttpMessageHandler(ObsidianPortalAuthenticationOptions options)
		{
			HttpMessageHandler handler = options.BackChannelHttpHandler ?? new WebRequestHandler();

			var webRequestHandler = handler as WebRequestHandler;
			if (webRequestHandler == null)
			{
				if (options.BackChannelCertificateValidator != null)
				{
					throw new InvalidOperationException("Exception_ValidatorHandlerMismatch");
				}
			}
			else if (options.BackChannelCertificateValidator != null)
			{
				webRequestHandler.ServerCertificateValidationCallback = options.BackChannelCertificateValidator.Validate;
			}

			return handler;
		}

	}
}