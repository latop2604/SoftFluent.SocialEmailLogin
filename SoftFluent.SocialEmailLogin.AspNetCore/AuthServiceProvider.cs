using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.AspNetCore.Http;
using SoftFluent.SocialEmailLogin.Utilities;

namespace SoftFluent.SocialEmailLogin
{
    public class AuthServiceProvider
    {
        public static string UnreservedCharacterSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        public static string ProviderParameter = "__provider__";
        public static string OptionsParameter = "__o__";
        public static string UrlParameter = "__url__";
        public static string ReturnUrlParameter = "returnurl";

        public string Name { get; set; }
        public string RequestCallback { get; set; }
        public AuthProtocol Protocol { get; set; }
        public string ConsumerKey { get; set; }
        public string ConsumerSecret { get; set; }
        public string FakeEmailDomain { get; set; }
        public string SuccessUrl { get; set; }
        public bool MaintainUserLocation { get; set; }
        public UserLocationStorageType UserLocationStorageType { get; set; }

        // oauth
        public string RequestTokenUrl { get; set; }
        public string UserAuthorizationUrl { get; set; }
        public string AccessTokenUrl { get; set; }

        // oauth2
        public string Scope { get; set; }
        public Dictionary<string, object> State { get; set; }
        public string ProfileUrl { get; set; }
        public string OAuth2AccessTokenMethod { get; set; }
        public string OAuth2ResponseType { get; set; }

        // openid
        public string DiscoveryUrl { get; set; }
        public string UserLoginUrl { get; protected set; } // determined by discovery
        public string OpenIdOAuthScope { get; set; }

        public event EventHandler<HeadersEventArgs> AfterCreateLoginOAuth20Headers;
        public event EventHandler<HeadersEventArgs> AfterCreateAccessTokenOAuth20Headers;

        public AuthServiceProvider()
        {
            RequestCallback = "requestcb.auth";
            OAuth2AccessTokenMethod = "GET";
            OAuth2ResponseType = "code";
            MaintainUserLocation = true;
            UserLocationStorageType = UserLocationStorageType.RedirectUri;
            State = new Dictionary<string, object>();
        }

        protected virtual void ThrowOnCallbackError(HttpContext context)
        {
            string error = context.Request.Query["error"];
            string errorDescription = context.Request.Query["error_description"];
            if (!string.IsNullOrEmpty(error))
            {
                if (!string.IsNullOrEmpty(errorDescription))
                {
                    error += ". " + errorDescription;
                }
                throw new AuthException("OA0007: User has denied access. " + error);
            }

            string denied = context.Request.Query["denied"];
            if (!string.IsNullOrEmpty(denied))
                throw new AuthException("OA0010: User has denied access.");

        }

        public virtual Task<UserData> GetUserData(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            ThrowOnCallbackError(context);

            switch (Protocol)
            {
                case AuthProtocol.OAuth20:
                    return GetUserDataOAuth20(context);

                case AuthProtocol.OpenIdOAuth:
                    return GetUserDataOpenIdOAuth(context);

                default:
                    throw new NotSupportedException();
            }
        }

        protected virtual async Task<UserData> GetUserDataOpenIdOAuth(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            // we need to check it's a good answer coming from the openid provider, and not an XSRF attack, before we can consume the email

            // http://openid.net/specs/openid-authentication-2_0.html 11.4.2.1.  Request Parameters
            // https://groups.google.com/forum/?fromgroups=#!topic/google-federated-login-api/wob1hEqWStc

            if (string.IsNullOrEmpty(UserLoginUrl))
            {
                await DiscoverOpenId();
                if (string.IsNullOrEmpty(UserLoginUrl))
                    throw new AuthException("OA0003: Unable to determine OpenId user login url.");
            }

            var request = (HttpWebRequest)WebRequest.Create(UserLoginUrl);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            using (var stream = await request.GetRequestStreamAsync())
            {
                using (var writer = new StreamWriter(stream))
                {
                    int i = 0;
                    foreach (string key in context.Request.Query.Keys)
                    {
                        string value = key == "openid.mode" ? "check_authentication" : context.Request.Query[key].ToString();
                        if (i > 0)
                        {
                            writer.Write('&');
                        }
                        else
                        {
                            i++;
                        }
                        writer.Write(key);
                        writer.Write('=');
                        writer.Write(WebUtility.UrlEncode(value));
                    }
                }
            }

            string result = await Execute(request);
            if (string.IsNullOrEmpty(result))
                return null;

            if (!result.Contains("is_valid:true"))
                return null;

            return GetUserData(context.Request);
        }

        protected virtual UserData GetUserData(HttpRequest httpRequest)
        {
            throw new NotImplementedException();
        }

        protected virtual void OnAfterCreateAccessTokenOAuth20Headers(object sender, HeadersEventArgs e)
        {
            AfterCreateAccessTokenOAuth20Headers?.Invoke(sender, e);
        }

        protected virtual void OnAfterCreateAccessTokenOAuth20Headers(IDictionary<string, string> headers)
        {
        }

        protected virtual async Task<string> GetAccessTokenOAuth20(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            string code = context.Request.Query["code"];
            if (string.IsNullOrEmpty(code))
                return null;

            var headers = new Dictionary<string, string>();
            headers.Add("client_id", ConsumerKey);
            headers.Add("client_secret", ConsumerSecret);
            headers.Add("code", code);
            headers.Add("grant_type", "authorization_code");
            string state = context.Request.Query["state"];
            if (!string.IsNullOrWhiteSpace(state))
            {
                headers.Add("state", state);
            }
            headers.Add("redirect_uri", GetRedirectUri(context));
            OnAfterCreateAccessTokenOAuth20Headers(headers);
            OnAfterCreateAccessTokenOAuth20Headers(this, new HeadersEventArgs(context, headers));

            HttpWebRequest request;
            if (OAuth2AccessTokenMethod == "POST")
            {
                request = (HttpWebRequest)WebRequest.Create(AccessTokenUrl);
                request.Method = OAuth2AccessTokenMethod;
                request.ContentType = "application/x-www-form-urlencoded";
                string authHeaders = SerializeOAuthHeaders(headers, "GET", true);
                byte[] bytes = Encoding.UTF8.GetBytes(authHeaders);
                //request.ContentLength = bytes.Length;
                using (var requestStream = await request.GetRequestStreamAsync())
                {
                    requestStream.Write(bytes, 0, bytes.Length);
                }
            }
            else
            {
                request = (HttpWebRequest)WebRequest.Create(AccessTokenUrl + "?" + SerializeOAuthHeaders(headers, "GET", true));
            }

            var exec = await ExecuteWithContentType(request);
            string ct =exec.Item2;
            string result = exec.Item1;
            if (string.IsNullOrEmpty(result))
                return null;

            string token = null;
            if (!string.IsNullOrEmpty(ct) &&
                (ct.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0 || ct.IndexOf("javascript", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                IDictionary<string, object> res = Extensions.JsonDeserialize(result);
                object at;
                if (res != null && res.TryGetValue("access_token", out at))
                {
                    var accessToken = at as IDictionary<string, object>;
                    if (accessToken != null) // Yammer
                    {
                        if (accessToken.TryGetValue("token", out at))
                        {
                            token = $"{at}";
                        }
                    }
                    else
                    {
                        token = $"{at}";
                    }
                }
            }
            else
            {
                var qs = Extensions.ParseQueryString(result);
                token = qs["access_token"];
            }
            return token;
        }

        protected async Task<UserData> GetUserDataOAuth20(HttpContext context)
        {
            string token = await GetAccessTokenOAuth20(context);
            if (string.IsNullOrWhiteSpace(token))
                return null;

            return await GetUserData(token);
        }

        private string GetRedirectUri(HttpContext context)
        {
            string absoluteApplicationPath = GetAbsoluteApplicationPath(context);
            if (string.IsNullOrEmpty(absoluteApplicationPath) || absoluteApplicationPath[absoluteApplicationPath.Length - 1] != '/')
            {
                absoluteApplicationPath += "/";
            }

            string redirectUri = absoluteApplicationPath + RequestCallback;

            var uriBuilder = new UriBuilder(redirectUri);
            if (UserLocationStorageType == UserLocationStorageType.RedirectUri)
            {
                var queryStringValues = Extensions.ParseQueryString(uriBuilder.Query);
                queryStringValues[ProviderParameter] = Name;
                queryStringValues[OptionsParameter] = LoginOptions.ToString("D");

                if (MaintainUserLocation)
                {
                    string urlParameterValue = context.Request.Query[UrlParameter];
                    if (!IsUrlLocalToHost(urlParameterValue))
                    {
                        urlParameterValue = context.Request.Query[ReturnUrlParameter];
                    }
                    if (!IsUrlLocalToHost(urlParameterValue))
                    {
                        urlParameterValue = SuccessUrl;
                    }

                    queryStringValues[UrlParameter] = urlParameterValue;
                }

                uriBuilder.Query = Extensions.BuildQueryString(queryStringValues);
            }

            return uriBuilder.Uri.AbsoluteUri;
        }

        protected virtual HttpWebRequest CreateGetOAuth20Request(string accessToken)
        {
            string separator = ProfileUrl.Contains("?") ? "&" : "?";
            return (HttpWebRequest)WebRequest.Create(ProfileUrl + separator + "access_token=" + accessToken);
        }

        protected virtual async Task<UserData> GetUserData(string accessToken)
        {
            HttpWebRequest request = CreateGetOAuth20Request(accessToken);

            string result = await Execute(request);

            return GetUserData(Extensions.JsonDeserialize(result));
        }

        protected virtual UserData GetUserData(IDictionary<string, object> data)
        {
            return CreateUserData(data);
        }

        public AuthLoginOptions LoginOptions { get; private set; }

        public virtual async Task Login(AuthLoginOptions options, HttpContext context)
        {
            LoginOptions = options;
            switch (Protocol)
            {
                case AuthProtocol.OAuth10a:
                    await LoginOAuth10a(context);
                    break;

                case AuthProtocol.OpenIdOAuth:
                    await LoginOpenIdOAuth(context);
                    break;

                case AuthProtocol.OAuth20:
                    LoginOAuth20(context);
                    break;

                default:
                    throw new NotSupportedException();
            }
        }

        protected virtual void OnAfterCreateLoginOAuth20Headers(object sender, HeadersEventArgs e)
        {
            AfterCreateLoginOAuth20Headers?.Invoke(sender, e);
        }

        protected virtual void OnAfterCreateLoginOAuth20Headers(IDictionary<string, string> headers)
        {
        }

        // http://tools.ietf.org/html/draft-ietf-oauth-v2-31
        protected virtual void LoginOAuth20(HttpContext context)
        {
            // http://openid.net/specs/openid-authentication-2_0.html
            var headers = new Dictionary<string, string>();
            headers.Add("client_id", ConsumerKey);
            headers.Add("response_type", OAuth2ResponseType);
            if (!string.IsNullOrEmpty(Scope))
            {
                headers.Add("scope", Scope);
            }

            var state = State.ToDictionary(kvp => kvp.Key, kvp => kvp.Value); // Clone the default state
            if (UserLocationStorageType == UserLocationStorageType.State)
            {
                state[ProviderParameter] = Name;
                state[OptionsParameter] = (int)LoginOptions;

                if (MaintainUserLocation)
                {
                    string ru = context.Request.Query[ReturnUrlParameter];
                    if (IsUrlLocalToHost(ru))
                    {
                        state[UrlParameter] = ru;
                    }
                    else if (IsUrlLocalToHost(SuccessUrl))
                    {
                        state[UrlParameter] = SuccessUrl;
                    }
                }
            }


            if (state.Count > 0)
            {
                headers.Add("state", WebUtility.UrlEncode((Extensions.JsonSerialize(state))));
            }
            headers.Add("redirect_uri", GetRedirectUri(context));
            OnAfterCreateLoginOAuth20Headers(headers);
            OnAfterCreateLoginOAuth20Headers(this, new HeadersEventArgs(context, headers));
            context.Response.Redirect(UserAuthorizationUrl + "?" + SerializeOAuthHeaders(headers, null, true), false);
        }

        protected virtual async Task LoginOpenIdOAuth(HttpContext context)
        {
            if (string.IsNullOrEmpty(UserLoginUrl))
            {
                await DiscoverOpenId();
                if (string.IsNullOrEmpty(UserLoginUrl))
                    throw new AuthException("OA0004: Unable to determine OpenId user login url.");
            }

            // http://openid.net/specs/openid-authentication-2_0.html
            var headers = new Dictionary<string, string>();
            headers.Add("openid.ns", "http://specs.openid.net/auth/2.0");
            headers.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select");
            headers.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select");
            headers.Add("openid.return_to", GetRedirectUri(context));
            headers.Add("openid.realm", GetAbsoluteApplicationPath(context));
            headers.Add("openid.mode", "checkid_setup");
            headers.Add("openid.ns.pape", "http://specs.openid.net/extensions/pape/1.0");
            headers.Add("openid.ns.max_auth_age", "0");
            headers.Add("openid.ns.ax", "http://openid.net/srv/ax/1.0");

            // http://openid.net/specs/openid-attribute-exchange-1_0.html
            headers.Add("openid.ax.mode", "fetch_request");
            SetOpenIdOAuthAttributes(headers);

            // oauth
            headers.Add("openid.ns.oauth", "http://specs.openid.net/extensions/oauth/1.0");
            headers.Add("openid.oauth.consumer", ConsumerKey);

            context.Response.Redirect(UserLoginUrl + "?" + SerializeOAuthHeaders(headers, null, true), false);
        }

        protected virtual void SetOpenIdOAuthAttributes(IDictionary<string, string> headers)
        {
            headers.Add("openid.ax.type.email", "http://axschema.org/contact/email");
            headers.Add("openid.ax.required", OpenIdOAuthScope ?? "email");
        }

        // http://openid.net/specs/openid-authentication-2_0.html#html_disco
        protected virtual async Task DiscoverOpenId()
        {
            using (var wc = new HttpClient())
            {
                string xrds = await wc.GetStringAsync(DiscoveryUrl);
                var doc = new XmlDocument();
                doc.LoadXml(xrds);
                var mgr = new XmlNamespaceManager(new NameTable());
                mgr.AddNamespace("x", "xri://$xrd*($v*2.0)");
                XmlNode node = doc.SelectSingleNode("//x:URI", mgr);
                if (node != null)
                {
                    UserLoginUrl = node.InnerText;
                }
            }
        }

        private static async Task<string> Execute(HttpWebRequest request)
        {
            return (await ExecuteWithContentType(request)).Item1;
        }

        private static async Task<Tuple<string,string>> ExecuteWithContentType(HttpWebRequest request)
        {
            try
            {
                using (var response = (HttpWebResponse) await request.GetResponseAsync())
                {
                    using (var stream = response.GetResponseStream())
                    {
                        using (var reader = new StreamReader(stream))
                        {
                            return Tuple.Create(reader.ReadToEnd(),  response.ContentType);
                        }
                    }
                }
            }
            catch (WebException we)
            {
                string text = null;
                if (we.Response != null)
                {
                    using (var reader = new StreamReader(we.Response.GetResponseStream()))
                    {
                        text = reader.ReadToEnd();
                    }
                }

                if (string.IsNullOrEmpty(text))
                    throw;

                throw new AuthException("OA0005: An OAuth error has occured. " + text, we);
            }
        }

        public static string SerializeOAuthHeaders(IEnumerable<KeyValuePair<string, string>> headers, string method)
        {
            return SerializeOAuthHeaders(headers, method, false);
        }

        public static string SerializeOAuthHeaders(IEnumerable<KeyValuePair<string, string>> headers, string method, bool encode)
        {
            var sb = new StringBuilder();
            if (method == "POST")
            {
                foreach (var header in headers)
                {
                    if (sb.Length > 0)
                    {
                        sb.Append(',');
                    }
                    sb.Append(encode ? WebUtility.UrlEncode(header.Key) : header.Key);
                    sb.Append('=');
                    sb.Append('"');
                    sb.Append(encode ? WebUtility.UrlEncode(header.Value) : header.Value);
                    sb.Append('"');
                }
            }
            else // GET
            {
                foreach (var header in headers)
                {
                    if (sb.Length > 0)
                    {
                        sb.Append('&');
                    }
                    sb.Append(encode ? WebUtility.UrlEncode(header.Key) : header.Key);
                    sb.Append('=');
                    sb.Append(encode ? WebUtility.UrlEncode(header.Value) : header.Value);
                }
            }
            return sb.ToString();
        }

        protected virtual async Task LoginOAuth10a(HttpContext context)
        {
            string method = "POST";

            var headers = new Dictionary<string, string>();
            headers["oauth_consumer_key"] = ConsumerKey;
            headers["oauth_signature_method"] = "HMAC-SHA1";
            headers["oauth_timestamp"] = BuildOAuthTimestamp();
            headers["oauth_nonce"] = BuildNonce();
            headers["oauth_version"] = "1.0";
            headers["oauth_callback"] = EncodeParameter(GetRedirectUri(context));
            headers["oauth_signature"] = EncodeParameter(SignOAuthRequest(method, RequestTokenUrl, headers, null));
            HttpWebRequest request;
            if (method == "POST")
            {
                request = (HttpWebRequest)WebRequest.Create(RequestTokenUrl);
                request.Headers["Authorization"] = "OAuth " + SerializeOAuthHeaders(headers, method);
            }
            else
            {
                request = (HttpWebRequest)WebRequest.Create(RequestTokenUrl + "?" + SerializeOAuthHeaders(headers, method));
            }
            request.Method = method;

            try
            {
                using (var response = (HttpWebResponse) await request.GetResponseAsync())
                using (var stream = response.GetResponseStream())
                using (var reader = new StreamReader(stream))
                {
                    var qs = Extensions.ParseQueryString(reader.ReadToEnd());
                    if (!qs.GetValue("oauth_callback_confirmed", false))
                        throw new AuthException("OA0001: OAuth callback was not confirmed.");

                    string requestToken = qs.GetValue("oauth_token", (string)null);
                    string tokenSecret = qs.GetValue("oauth_token_secret", (string)null);
                    context.Response.Redirect(UserAuthorizationUrl + "?oauth_token=" + requestToken, false);
                }
            }
            catch (WebException we)
            {
                string text = null;
                if (we.Response != null)
                {
                    using (var reader = new StreamReader(we.Response.GetResponseStream()))
                    {
                        text = reader.ReadToEnd();
                    }
                }
                if (string.IsNullOrEmpty(text))
                    throw;

                throw new AuthException("OA0009: An OAuth error has occured. " + text, we);
            }
        }

        public static string GetAbsoluteApplicationPath(HttpContext context)
        {
            string url = $"{context.Request.Scheme}://{context.Request.Host}";
            //url = url.Replace(":5000", "");
            return url;
        }

        public static string EncodeParameter(string name)
        {
            if (name == null)
                return null;

            var sb = new StringBuilder();
            foreach (char c in name)
            {
                if (UnreservedCharacterSet.IndexOf(c) != -1)
                {
                    sb.Append(c);
                }
                else
                {
                    sb.AppendFormat("%{0:X2}", (int)c);
                }
            }
            return sb.ToString();
        }

        // http://oauth.net/core/1.0a/ Section 9.11
        private sealed class QueryParameterComparer : IComparer<KeyValuePair<string, string>>
        {
            public int Compare(KeyValuePair<string, string> x, KeyValuePair<string, string> y)
            {
                if (x.Key == y.Key)
                    return string.CompareOrdinal(x.Value, y.Value);

                return string.CompareOrdinal(x.Key, y.Key);
            }
        }

        // http://oauth.net/core/1.0a/ Section 9.13
        protected virtual string SignOAuthRequest(string method, string uri, IDictionary<string, string> headers, string tokenSecret)
        {
            if (method == null)
                throw new ArgumentNullException(nameof(method));

            if (uri == null)
                throw new ArgumentNullException(nameof(uri));

            var sb = new StringBuilder(method.ToUpperInvariant());
            sb.Append('&');
            sb.Append(EncodeParameter(uri));

            var parameters = new List<KeyValuePair<string, string>>(headers);
            parameters.Sort(new QueryParameterComparer());

            string sparams = null;
            for (int i = 0; i < parameters.Count; i++)
            {
                if (i > 0)
                {
                    sparams += '&';
                }
                sparams += parameters[i].Key + '=' + parameters[i].Value;
            }

            sb.Append('&');
            sb.Append(EncodeParameter(sparams));

            var hash = new HMACSHA1();
            hash.Key = Encoding.ASCII.GetBytes($"{EncodeParameter(ConsumerSecret)}&{EncodeParameter(tokenSecret)}");
            return Convert.ToBase64String(hash.ComputeHash(Encoding.ASCII.GetBytes(sb.ToString())));
        }

        protected virtual string BuildNonce()
        {
            return Guid.NewGuid().ToString("N");
        }

        protected virtual string BuildOAuthTimestamp()
        {
            // the timestamp is expressed in the number of seconds since January 1, 1970 00:00:00 GMT
            return ((long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0)).TotalSeconds).ToString();
        }

        public static bool IsUrlLocalToHost(string url)
        {
            return !string.IsNullOrWhiteSpace(url) &&
                ((url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'))) || (url.Length > 1 && url[0] == '~' && url[1] == '/'));
        }

        protected static string DecodeUrlParameter(string param)
        {
            return param == null ? null : WebUtility.UrlDecode(param).Nullify(trim: true);
        }

        protected virtual UserData CreateUserData(IDictionary<string, object> data)
        {
            return new UserData(data);
        }
    }
}
