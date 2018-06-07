using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CognitoSampleMVC.Startup))]
namespace CognitoSampleMVC
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
