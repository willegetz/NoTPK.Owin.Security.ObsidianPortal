using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using NoTPK.Owin.Security.ObsidianPortal.Messages;
using NoTPK.Owin.Security.ObsidianPortal.Providers;

namespace NoTPK.Owin.Security.ObsidianPortal
{
	public class ObsidianPortalAuthenticationHandler : AuthenticationHandler<ObsidianPortalAuthenticationOptions>
	{
		private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
		private const string StateCookie = "__ObsidianPortalState";
		private const string RequestTokenEndpoint = "https://www.obsidianportal.com/oauth/request_token";
		private const string AuthenticationEndpoint = "https://www.obsidianportal.com/oauth/authorize?oauth_token=";
		private const string AccessTokenEndpoint = "https://www.obsidianportal.com/oauth/access_token";
		private const string UnserInfoRequest = "http://api.obsidianportal.com/v1/users/me.json";

		private readonly HttpClient _httpClient;
		private readonly ILogger _logger;

		public ObsidianPortalAuthenticationHandler(HttpClient httpClient, ILogger logger)
		{
			_httpClient = httpClient;
			_logger = logger;
		}

		public override async Task<bool> InvokeAsync()
		{
			if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
			{
				return await InvokeReturnPathAsync();
			}
			return false;
		}

		protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
		{
			AuthenticationProperties properties = null;
			try
			{
				IReadableStringCollection query = Request.Query;
				string protectedRequestToken = Request.Cookies[StateCookie];

				RequestToken requestToken = Options.StateDataFormat.Unprotect(protectedRequestToken);
				if (requestToken == null)
				{
					_logger.WriteWarning("invalid state");
					return null;
				}

				properties = requestToken.Properties;

				string returnedToken = query.Get("oauth_token");
				if (string.IsNullOrWhiteSpace(returnedToken))
				{
					_logger.WriteWarning("Missing oauth_token");
					return NullIdentityTicket(properties);
				}

				if (returnedToken != requestToken.Token)
				{
					_logger.WriteWarning("Unmatched token");
					return NullIdentityTicket(properties);
				}

				string oauthVerifier = query.Get("oauth_verifier");
				if (string.IsNullOrWhiteSpace(oauthVerifier))
				{
					_logger.WriteWarning("Missing or blank oauth_verifier");
					return NullIdentityTicket(properties);
				}

				AccessToken accessToken = await ObtainAccessTokenAsync(Options.ConsumerKey, Options.ConsumerSecret, requestToken, oauthVerifier);


				var context = new ObsidianPortalAuthenticatedContext(Context, accessToken.UserId, accessToken.ScreenName, accessToken.Token, accessToken.TokenSecret);

				var userInfo = await GetUserInfo(Options.ConsumerKey, Options.ConsumerSecret, accessToken, UnserInfoRequest, HttpMethod.Get);
				var userId = userInfo[0];
				var userName = userInfo[1];

				accessToken.UserId = userId;
				accessToken.ScreenName = userName;

				context.Identity = new ClaimsIdentity(
					new[]
					{
						new Claim(ClaimTypes.Authentication, accessToken.Token), 
						new Claim(ClaimTypes.NameIdentifier, accessToken.UserId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
						new Claim(ClaimTypes.Name, accessToken.ScreenName, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
						new Claim("urn:obsidianprotal:userid", accessToken.UserId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
						new Claim("urn:obsidianportal:screenname", accessToken.ScreenName, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType)
					},
					Options.AuthenticationType,
					ClaimsIdentity.DefaultNameClaimType,
					ClaimsIdentity.DefaultRoleClaimType);
				context.Properties = requestToken.Properties;

				Response.Cookies.Delete(StateCookie);

				await Options.Provider.Authenticated(context);

				return new AuthenticationTicket(context.Identity, context.Properties);
			}
			catch (Exception ex)
			{
				_logger.WriteError("Authentication failed", ex);
				return NullIdentityTicket(properties);
			}
		}

		//		private Json GetUserInfo(string _consumerKey, string _consumerSecret, string _token, string _tokenSecret)
		//		{
		//			HttpWebRequest request;
		//			WebResponse response;
		//			string timeStamp;
		//			string nonce;
		//			string outAddress;
		//			string outParams;
		//			string signature;
		//			string postHeader;
		//			OAuthBase oauth;
		//			Uri uri;
		//
		//			try
		//			{
		//
		//				timeStamp = GenerateTimeStamp();
		//				nonce = Guid.NewGuid().ToString("N");
		//
		//				uri = new Uri(UnserInfoRequest);
		//				signature = ComputeSignature(_consumerSecret, _tokenSecret, "");
		//					"GET", timeStamp, nonce, out outAddress, out outParams);
		//				signature = oauth.UrlEncode(signature);
		//
		//				postHeader = "OAuth oauth_nonce={0}, oauth_signature_method={1}, oauth_timestamp={2}, oauth_consumer_key={3}, oauth_token={5},  oauth_signature={4}, oauth_version=1.0";
		//				postHeader = string.Format(postHeader, nonce, "HMAC-SHA1", timeStamp, _consumerKey, signature, _token);
		//				request = WebRequest.Create(outAddress) as HttpWebRequest;
		//				request.Method = "GET";
		//				request.Headers.Add("Authorization:" + postHeader);
		//
		//				response = request.GetResponse();
		//			}
		//			catch (WebException ex)
		//			{
		//				throw new Exception(ex.Message + "\n" + GetResponseText(ex.Response));
		//			}
		//
		//			return GetResponseText(response);
		//		}

		protected override async Task ApplyResponseChallengeAsync()
		{
			if (Response.StatusCode != 401)
			{
				return;
			}

			AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

			if (challenge != null)
			{
				string requestPrefix = Request.Scheme + "://" + Request.Host;
				string callBackUrl = requestPrefix + RequestPathBase + Options.CallbackPath;

				AuthenticationProperties extra = challenge.Properties;
				if (string.IsNullOrEmpty(extra.RedirectUri))
				{
					extra.RedirectUri = requestPrefix + Request.PathBase + Request.Path + Request.QueryString;
				}

				RequestToken requestToken = await ObtainRequestTokenAsync(Options.ConsumerKey, Options.ConsumerSecret, callBackUrl, extra);

				if (requestToken.CallbackConfirmed)
				{
					string obsidianPortalAuthenticationEndpoint = AuthenticationEndpoint + requestToken.Token;

					var cookieOptions = new CookieOptions()
					{
						HttpOnly = true,
						Secure = Request.IsSecure,
					};

					Response.Cookies.Append(StateCookie, Options.StateDataFormat.Protect(requestToken), cookieOptions);

					var redirectContext = new ObsidianPortalApplyRedirectContext(Context, Options, extra, obsidianPortalAuthenticationEndpoint);
					Options.Provider.ApplyRedirect(redirectContext);
				}
				else
				{
					_logger.WriteError("requestToken CallbackConfirmed!=true");
				}

			}
		}

		private async Task<bool> InvokeReturnPathAsync()
		{
			AuthenticationTicket model = await AuthenticateAsync();
			if (model == null)
			{
				_logger.WriteWarning("Invalid return state. Unable to redirect");
				Response.StatusCode = 500;
				return true;
			}

			var context = new ObsidianPortalReturnEndpointContext(Context, model)
			{
				SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
				RedirectUri = model.Properties.RedirectUri,
			};
			model.Properties.RedirectUri = null;

			await Options.Provider.ReturnEndpoint(context);

			if (context.SignInAsAuthenticationType != null && context.Identity != null)
			{
				ClaimsIdentity signInIdentity = context.Identity;
				if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.OrdinalIgnoreCase))
				{
					signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
				}
				Context.Authentication.SignIn(context.Properties, signInIdentity);
			}

			if (!context.IsRequestCompleted && context.RedirectUri != null)
			{
				if (context.Identity == null)
				{
					context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
				}
				Response.Redirect(context.RedirectUri);
				context.RequestCompleted();
			}

			return context.IsRequestCompleted;
		}

		private async Task<RequestToken> ObtainRequestTokenAsync(string consumerKey, string consumerSecret, string callBackUri, AuthenticationProperties properties)
		{
			_logger.WriteVerbose("ObtainRequestToken");

			string nonce = Guid.NewGuid().ToString("N");
			var authorizationParts = new SortedDictionary<string, string>
			{
				{ "oauth_callback", callBackUri },
				{ "oauth_consumer_key", consumerKey }, //+
				{ "oauth_nonce", nonce }, //+
				{ "oauth_signature_method", "HMAC-SHA1" }, //+
				{ "oauth_timestamp", GenerateTimeStamp() }, //+
				{ "oauth_version", "1.0" } //+
			};

			var parameterBuilder = new StringBuilder();
			foreach (var authorizationKey in authorizationParts)
			{
				parameterBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(authorizationKey.Key),
					Uri.EscapeDataString(authorizationKey.Value));
			}
			parameterBuilder.Length--;
			string paramaterString = parameterBuilder.ToString();

			var canonicalizedRequestBuilder = new StringBuilder();
			canonicalizedRequestBuilder.Append(HttpMethod.Post.Method);
			canonicalizedRequestBuilder.Append("&");
			canonicalizedRequestBuilder.Append(Uri.EscapeDataString(RequestTokenEndpoint));
			//			canonicalizedRequestBuilder.Append(Uri.EscapeDataString(AccessTokenEndpoint));
			canonicalizedRequestBuilder.Append("&");
			var escapeDataString = Uri.EscapeDataString(paramaterString);
			canonicalizedRequestBuilder.Append(escapeDataString);

			string signature = ComputeSignature(consumerSecret, null, canonicalizedRequestBuilder.ToString());
			authorizationParts.Add("oauth_signature", signature);

			var authorizationHeaderBuilder = new StringBuilder();
			authorizationHeaderBuilder.Append("OAuth ");
			foreach (var authorizationPart in authorizationParts)
			{
				authorizationHeaderBuilder.AppendFormat("{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString(authorizationPart.Value));
			}
			authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

			var request = new HttpRequestMessage(HttpMethod.Post, RequestTokenEndpoint);
			request.Headers.Add("Authorization", authorizationHeaderBuilder.ToString());
			HttpResponseMessage response = await _httpClient.SendAsync(request, Request.CallCancelled);
			response.EnsureSuccessStatusCode();
			string responseText = await response.Content.ReadAsStringAsync();

			IFormCollection responseParameters = WebHelpers.ParseForm(responseText);
			if (string.Equals(responseParameters["oauth_callback_confirmed"], "true", StringComparison.InvariantCulture))
			{
				return new RequestToken { Token = Uri.UnescapeDataString(responseParameters["oauth_token"]), TokenSecret = Uri.UnescapeDataString(responseParameters["oauth_token_secret"]), CallbackConfirmed = true, Properties = properties };
			}

			return new RequestToken();
		}

		private async Task<AccessToken> ObtainAccessTokenAsync(string consumerKey, string consumerSecret, RequestToken token, string verifier)
		{
			_logger.WriteVerbose("ObtainAccessToken");

			string nonce = Guid.NewGuid().ToString("N");

			var authorizationParts = new SortedDictionary<string, string>
			{
				{ "oauth_consumer_key", consumerKey },
				{ "oauth_nonce", nonce },
				{ "oauth_signature_method", "HMAC-SHA1" },
				{ "oauth_token", token.Token },
				{ "oauth_timestamp", GenerateTimeStamp() },
				{ "oauth_verifier", verifier },
				{ "oauth_version", "1.0" },
			};

			var parameterBuilder = new StringBuilder();
			foreach (var authorizationKey in authorizationParts)
			{
				parameterBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(authorizationKey.Key), Uri.EscapeDataString(authorizationKey.Value));
			}
			parameterBuilder.Length--;
			string parameterString = parameterBuilder.ToString();

			var canonicalizedRequestBuilder = new StringBuilder();
			canonicalizedRequestBuilder.Append(HttpMethod.Post.Method);
			canonicalizedRequestBuilder.Append("&");
			canonicalizedRequestBuilder.Append(Uri.EscapeDataString(AccessTokenEndpoint));
			canonicalizedRequestBuilder.Append("&");
			canonicalizedRequestBuilder.Append(Uri.EscapeDataString(parameterString));

			string signature = ComputeSignature(consumerSecret, token.TokenSecret, canonicalizedRequestBuilder.ToString());
			authorizationParts.Add("oauth_signature", signature);
			authorizationParts.Remove("oauth_verifier");

			var authorizationHeaderBuilder = new StringBuilder();
			authorizationHeaderBuilder.Append("OAuth ");
			foreach (var authorizationPart in authorizationParts)
			{
				authorizationHeaderBuilder.AppendFormat(
					"{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString(authorizationPart.Value));
			}
			authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

			var request = new HttpRequestMessage(HttpMethod.Post, AccessTokenEndpoint);
			request.Headers.Add("Authorization", authorizationHeaderBuilder.ToString());

			var formPairs = new List<KeyValuePair<string, string>>()
			{
				new KeyValuePair<string, string>("oauth_verifier", verifier)
			};

			request.Content = new FormUrlEncodedContent(formPairs);

			HttpResponseMessage response = await _httpClient.SendAsync(request, Request.CallCancelled);

			if (!response.IsSuccessStatusCode)
			{
				_logger.WriteError("AccessToken request failed with a status code of " + response.StatusCode);
				response.EnsureSuccessStatusCode(); // throw
			}

			string responseText = await response.Content.ReadAsStringAsync();

			IFormCollection responseParameters = WebHelpers.ParseForm(responseText);

			var unescapedOauthToken = Uri.UnescapeDataString(responseParameters["oauth_token"]);
			var unescapedOauthSecret = Uri.UnescapeDataString(responseParameters["oauth_token_secret"]);
			return new AccessToken
			{
				Token = unescapedOauthToken,
				TokenSecret = unescapedOauthSecret,
			};
		}
		private static string GenerateTimeStamp()
		{
			TimeSpan secondsSinceUnixEpocStart = DateTime.UtcNow - Epoch;
			return Convert.ToInt64(secondsSinceUnixEpocStart.TotalSeconds).ToString(CultureInfo.InvariantCulture);
		}

		private static string ComputeSignature(string consumerSecret, string tokenSecret, string signatureData)
		{
			using (var algorithm = new HMACSHA1())
			{
				var escapedConsumerSecret = Uri.EscapeDataString(consumerSecret);
				var escapedTokenSecret = string.IsNullOrEmpty(tokenSecret) ? string.Empty : Uri.EscapeDataString(tokenSecret);

				algorithm.Key = Encoding.ASCII.GetBytes(string.Format(CultureInfo.InvariantCulture, "{0}&{1}", escapedConsumerSecret, escapedTokenSecret));
				byte[] hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(signatureData));
				return Convert.ToBase64String(hash);
			}
		}

		private static AuthenticationTicket NullIdentityTicket(AuthenticationProperties properties)
		{
			return new AuthenticationTicket(null, properties);
		}

		private async Task<string[]> GetUserInfo(string consumerKey, string consumerSecret, AccessToken token, string obsidianPortalUri, HttpMethod webmethod)
		{
			string nonce = Guid.NewGuid().ToString("N");

			var authorizationParts = new SortedDictionary<string, string>
			{
				{ "oauth_consumer_key", consumerKey },
				{ "oauth_nonce", nonce },
				{ "oauth_signature_method", "HMAC-SHA1" },
				{ "oauth_token", token.Token },
				{ "oauth_timestamp", GenerateTimeStamp() },
				{ "oauth_version", "1.0" },
			};

			var parameterBuilder = new StringBuilder();
			foreach (var authorizationKey in authorizationParts)
			{
				parameterBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(authorizationKey.Key), Uri.EscapeDataString(authorizationKey.Value));
			}
			parameterBuilder.Length--;
			string parameterString = parameterBuilder.ToString();

			var canonicalizedRequestBuilder = new StringBuilder();
			canonicalizedRequestBuilder.Append(webmethod.Method);
			canonicalizedRequestBuilder.Append("&");
			canonicalizedRequestBuilder.Append(Uri.EscapeDataString(obsidianPortalUri));
			canonicalizedRequestBuilder.Append("&");
			canonicalizedRequestBuilder.Append(Uri.EscapeDataString(parameterString));

			string signature = ComputeSignature(consumerSecret, token.TokenSecret, canonicalizedRequestBuilder.ToString());
			authorizationParts.Add("oauth_signature", signature);
			authorizationParts.Remove("oauth_verifier");

			var authorizationHeaderBuilder = new StringBuilder();
			authorizationHeaderBuilder.Append("OAuth ");
			foreach (var authorizationPart in authorizationParts)
			{
				authorizationHeaderBuilder.AppendFormat(
					"{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString(authorizationPart.Value));
			}
			authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

			var request = new HttpRequestMessage(webmethod, obsidianPortalUri);
			request.Headers.Add("Authorization", authorizationHeaderBuilder.ToString());

			HttpResponseMessage response = await _httpClient.SendAsync(request, Request.CallCancelled);

			if (!response.IsSuccessStatusCode)
			{
				_logger.WriteError("AccessToken request failed with a status code of " + response.StatusCode);
				response.EnsureSuccessStatusCode(); // throw
			}

			string responseText = await response.Content.ReadAsStringAsync();
			dynamic decode = JObject.Parse(responseText);
			var userId = decode.id;
			var userName = decode.username;

			var userInfo = new string[] { userId, userName };
			return userInfo;
		}
 
	}
}