using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace SoftFluent.SocialEmailLogin.DemoCore
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            var authenticationElement = new Configuration.AuthenticationElement()
            {
                MaximumRetryCount = 10,
                RetryInterval = 50,
                ServiceProviders =
                {
                    new Configuration.ServiceProviderElement()
                    {
                        ConsumerKey = "XXX",
                        ConsumerSecret = "YYY",
                        UserLocationStorageType = UserLocationStorageType.RedirectUri,
                        Name = "Facebook",
                    },
                    new Configuration.ServiceProviderElement()
                    {
                        ConsumerKey = "XXX",
                        ConsumerSecret = "YYY",
                        Name = "Google",
                    },
                    new Configuration.ServiceProviderElement()
                    {
                        ConsumerKey = "XXX",
                        ConsumerSecret = "YYY",
                        Name = "Microsoft",
                    },
                    new Configuration.ServiceProviderElement()
                    {
                        ConsumerKey = "XXX",
                        ConsumerSecret = "YYY",
                        Name = "LinkedIn",
                    },
                    new Configuration.ServiceProviderElement()
                    {
                        ConsumerKey = "XXX",
                        ConsumerSecret = "YYY",
                        Name = "Yahoo",
                    },
                    new Configuration.ServiceProviderElement()
                    {
                        ConsumerKey = "XXX",
                        ConsumerSecret = "YYY",
                        Name = "Twitter",
                    },
                    new Configuration.ServiceProviderElement()
                    {
                        ConsumerKey = "XXX",
                        ConsumerSecret = "YYY",
                        Name = "Yammer",
                    }
                }
            };

            authenticationElement.ServiceProviders.Add(new Configuration.ServiceProviderElement()
            {
                ConsumerKey = "XXX",
                ConsumerSecret = "XXX",
                UserLocationStorageType = UserLocationStorageType.RedirectUri,
                Name = "Facebook",
            });

            authenticationElement.ServiceProviders.Add(new Configuration.ServiceProviderElement()
            {
                ConsumerKey = "XXX",
                ConsumerSecret = "XXX",
                UserLocationStorageType = UserLocationStorageType.RedirectUri,
                Name = "Facebook",
            });

            authenticationElement.ServiceProviders.Add(new Configuration.ServiceProviderElement()
            {
                ConsumerKey = "XXX",
                ConsumerSecret = "XXX",
                UserLocationStorageType = UserLocationStorageType.RedirectUri,
                Name = "Facebook",
            });

            authenticationElement.ServiceProviders.Add(new Configuration.ServiceProviderElement()
            {
                ConsumerKey = "XXX",
                ConsumerSecret = "XXX",
                UserLocationStorageType = UserLocationStorageType.RedirectUri,
                Name = "Facebook",
            });

            authenticationElement.ServiceProviders.Add(new Configuration.ServiceProviderElement()
            {
                ConsumerKey = "XXX",
                ConsumerSecret = "XXX",
                UserLocationStorageType = UserLocationStorageType.RedirectUri,
                Name = "Facebook",
            });

            services.AddSingleton(authenticationElement);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory, Configuration.AuthenticationElement authenticationElement)
        {
            loggerFactory.AddConsole();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseSocialEmailLogin(authenticationElement, LoginSuccess);

            app.Map("/GoLoggin", appBuilder => appBuilder.Run(async (context) =>
                await authenticationElement.GetServiceProvider(context.Request.Query["__provider__"])
                    ?.Login(AuthLoginOptions.None, context)
            ));

            app.Run(async (context) =>
            {
                if (context.Request.Path == "/GoLoggin")
                {
                    var provider = authenticationElement.GetServiceProvider(context.Request.Query["__provider__"]);
                    if (provider != null)
                    {
                        await provider.Login(AuthLoginOptions.None, context);
                        return;
                    }
                }

                await context.Response.WriteAsync(GetLoginPage());
            });
        }

        private static string GetLoginPage()
        {
            return @"<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"" />
    <title></title>
</head>
<body>
    choose a provider :
    <ul>
        <li><a href=""GoLoggin?__provider__=Google"">Google</a></li>
        <li><a href=""GoLoggin?__provider__=Facebook"">Facebook</a></li>
        <li>Twitter</li>
        <li>Live</li>
    </ul>
</body>
</html>";
        }

        private static async Task<bool> LoginSuccess(HttpContext context, AuthServiceProvider provider, AuthLoginOptions options, UserData userData)
        {
            await context.Response.WriteAsync($@"
<!DOCTYPE html>
<html>
    <head>
        <meta charset=""utf-8"" />
        <title>Titre</title>
    </head>
<body>
Hello <strong>{userData.Name}</strong> !<br/>
I will send you a mail here <em>{userData.Email}</em>
</body>
</html>
");
            return true;
        }
    }
}
