using System;
using System.Reflection;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    public class ServiceProviderElement
    {
        private AuthServiceProvider _authServiceProvider;

        public string Name { get; set; }

        private string _displayName;
        public string DisplayName
        {
            get
            {
                string name = _displayName;
                if (string.IsNullOrEmpty(name))
                    return Name;

                return name;
            }
            set
            {
                _displayName = value;
            }
        }

        public string TypeName { get; set; }

        public string ConsumerKey { get; set; }

        public string ConsumerSecret { get; set; }

        public string FakeEmailDomain { get; set; }

        public string RequestTokenUrl { get; set; }

        public string UserAuthorizationUrl { get; set; }

        public string DiscoveryUrl { get; set; }

        public string RequestCallback { get; set; }

        public string Scope { get; set; }

        public AuthProtocol Protocol { get; set; } = AuthProtocol.Undefined;

        public string SuccessUrl { get; set; }

        public bool MaintainUserLocation { get; set; } = true;

        public UserLocationStorageType UserLocationStorageType { get; set; } = UserLocationStorageType.State;

        public bool Enabled { get; set; } = true;

        public AuthServiceProvider AuthServiceProvider
        {
            get
            {
                if (_authServiceProvider == null)
                {
                    string typeName = TypeName;
                    Type type = null;
                    if (typeName != null)
                    {
                        type = Type.GetType(typeName, false);
                    }
                    if (type == null)
                    {
                        if (string.IsNullOrEmpty(typeName))
                        {
                            //SoftFluent.SocialEmailLogin.FacebookServiceProvider
                            typeName = typeof(AuthServiceProvider).Namespace + "." + Name + "ServiceProvider, " + typeof(AuthServiceProvider).GetTypeInfo().Assembly;
                        }

                        type = Type.GetType(typeName, true);
                    }

                    _authServiceProvider = Activator.CreateInstance(type) as AuthServiceProvider;
                    if (_authServiceProvider == null)
                        throw new Exception();

                    _authServiceProvider.Name = Name;
                    _authServiceProvider.UserLocationStorageType = UserLocationStorageType;

                    if (Protocol != AuthProtocol.Undefined)
                    {
                        _authServiceProvider.Protocol = Protocol;
                    }

                    _authServiceProvider.ConsumerKey = ConsumerKey;
                    _authServiceProvider.ConsumerSecret = ConsumerSecret;

                    if (!string.IsNullOrEmpty(FakeEmailDomain))
                    {
                        _authServiceProvider.FakeEmailDomain = FakeEmailDomain;
                    }

                    if (!string.IsNullOrEmpty(RequestTokenUrl))
                    {
                        _authServiceProvider.RequestTokenUrl = RequestTokenUrl;
                    }

                    if (!string.IsNullOrEmpty(UserAuthorizationUrl))
                    {
                        _authServiceProvider.UserAuthorizationUrl = UserAuthorizationUrl;
                    }

                    if (!string.IsNullOrEmpty(RequestCallback))
                    {
                        _authServiceProvider.RequestCallback = RequestCallback;
                    }

                    if (!string.IsNullOrEmpty(Scope))
                    {
                        _authServiceProvider.Scope = Scope;
                    }

                    if (!string.IsNullOrEmpty(DiscoveryUrl))
                    {
                        _authServiceProvider.DiscoveryUrl = DiscoveryUrl;
                    }

                    if (!string.IsNullOrEmpty(SuccessUrl))
                    {
                        _authServiceProvider.SuccessUrl = SuccessUrl;
                    }
                }
                return _authServiceProvider;
            }
        }
    }
}
