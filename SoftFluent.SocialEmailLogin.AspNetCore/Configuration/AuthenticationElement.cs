using System;
using System.Collections.Generic;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    public class AuthenticationElement
    {
        private readonly List<ServiceProviderElement> _serviceProviders = new List<ServiceProviderElement>();
        public virtual List<ServiceProviderElement> ServiceProviders => _serviceProviders;

        public virtual StringComparison ProviderNameComparison { get; set; } = StringComparison.OrdinalIgnoreCase;

        public virtual int MaximumRetryCount { get; set; } = 10;

        public virtual int RetryInterval { get; set; } = 50;

        public virtual AuthServiceProvider GetServiceProvider(string name)
        {
            return GetServiceProvider(name, ProviderNameComparison);
        }

        public virtual AuthServiceProvider GetServiceProvider(string name, StringComparison stringComparison)
        {
            if (name == null)
                return null;

            foreach (ServiceProviderElement provider in ServiceProviders)
            {
                if (provider.Enabled && string.Equals(provider.Name, name, ProviderNameComparison))
                    return provider.AuthServiceProvider;
            }
            return null;
        }
    }
}
