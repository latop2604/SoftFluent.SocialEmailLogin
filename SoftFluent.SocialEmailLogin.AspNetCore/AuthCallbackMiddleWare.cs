
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using SoftFluent.SocialEmailLogin.Configuration;
using SoftFluent.SocialEmailLogin.Utilities;

namespace SoftFluent.SocialEmailLogin.DemoCore
{
    public delegate Task<bool> AuthCallbackAuthenticate(HttpContext context, AuthServiceProvider provider, AuthLoginOptions options, UserData userData);
    public static class SocialEmailLoginExtensions
    {
        public static IApplicationBuilder UseSocialEmailLogin(this IApplicationBuilder builder, AuthenticationElement settings, AuthCallbackAuthenticate authenticate)
        {
            return builder.UseMiddleware<AuthCallbackMiddleware>(settings, authenticate);
        }
    }

    public class AuthCallbackMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly AuthenticationElement _settings;
        private readonly AuthCallbackAuthenticate _authenticate;

        public AuthCallbackMiddleware(RequestDelegate next, AuthenticationElement settings, AuthCallbackAuthenticate authenticate)
        {
            _next = next;
            _settings = settings;
            _authenticate = authenticate;
        }

        public async Task Invoke(HttpContext context)
        {
            if (context.Request.Path.Value.EndsWith(".auth"))
            {
                if (context == null)
                    throw new ArgumentNullException(nameof(context));

                var state = ReadStateQueryParameter(context);
                string providerName = GetValue(context, state, AuthServiceProvider.ProviderParameter) as string;
                if (providerName == null)
                    return;

                AuthenticationElement authenticationElement = GetAuthenticationElement();
                AuthServiceProvider provider = GetServiceProvider(providerName);
                if (provider == null)
                    return;

                AuthLoginOptions loginOptions;
                Enum.TryParse(GetValue(context, state, AuthServiceProvider.OptionsParameter)?.ToString(), out loginOptions);

                int attempt = 0;
                UserData userData = null;
                while (attempt < authenticationElement.MaximumRetryCount)
                {
                    try
                    {
                        userData = await provider.GetUserData(context);
                        break;
                    }
                    catch (Exception ex)
                    {
                        if (!OnGetUserDataError(ex, attempt))
                            break;

                        attempt++;
                        if (authenticationElement.RetryInterval > 0)
                        {
                            await Task.Delay(authenticationElement.RetryInterval);
                        }
                    }
                }

                if (userData == null)
                    return;

                await Authenticate(context, provider, loginOptions, userData);
            }
            else
            {
                await _next.Invoke(context);
            }
        }

        protected virtual AuthServiceProvider GetServiceProvider(string providerName)
        {
            return GetAuthenticationElement().GetServiceProvider(providerName);
        }

        protected virtual AuthenticationElement GetAuthenticationElement()
        {
            return _settings;
        }

        protected virtual bool OnGetUserDataError(Exception ex, int attempt)
        {
            if (ex is WebException)
                return true;

            return false;
        }

        protected virtual Task<bool> Authenticate(HttpContext context, AuthServiceProvider provider, AuthLoginOptions options, UserData userData)
        {
            return _authenticate(context, provider, options, userData);
        }

        protected virtual void RedirectUnauthorized(HttpContext context, bool allowRedirect)
        {
            //context.Response.StatusDescription = "Forbidden.";
            context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
            //context.Response.End();
        }

        protected virtual object GetValue(HttpContext context, IDictionary<string, object> state, string parameterName)
        {
            object value = ((string)context.Request.Query[parameterName]).Nullify(trim: true);
            if (value == null && state != null)
            {
                if (state.ContainsKey(parameterName))
                {
                    value = state[parameterName];
                }
            }
            return value;
        }

        protected virtual IDictionary<string, object> ReadStateQueryParameter(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            try
            {
                string st = context.Request.Query["state"];
                if (!string.IsNullOrWhiteSpace(st))
                    return Newtonsoft.Json.JsonConvert.DeserializeObject<IDictionary<string, object>>(WebUtility.UrlDecode(st));
            }
            catch
            {
            }

            return null;
        }
    }
}
