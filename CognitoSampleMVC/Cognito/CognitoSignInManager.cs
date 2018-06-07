using System.Data.Entity.Utilities;
using System.Security.Claims;
using System.Threading.Tasks;
using Amazon.CognitoIdentityProvider;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace CognitoSampleMVC.Cognito
{
    public class CognitoSignInManager : SignInManager<CognitoUser, string>
    {
        public CognitoSignInManager(CognitoUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        public override Task<ClaimsIdentity> CreateUserIdentityAsync(CognitoUser user)
        {
            return user.GenerateUserIdentityAsync((CognitoUserManager) UserManager);
        }

        public static CognitoSignInManager Create(IdentityFactoryOptions<CognitoSignInManager> options,
            IOwinContext context)
        {
            return new CognitoSignInManager(context.GetUserManager<CognitoUserManager>(), context.Authentication);
        }

        public override async Task<SignInStatus> PasswordSignInAsync(string userName, string password, bool isPersistent,
            bool shouldLockout)
        {
            if (this.UserManager == null)
                return SignInStatus.Failure;
            CognitoUser user = await UserManager.FindByNameAsync(userName).WithCurrentCulture();
            if ((object) user == null)
                return SignInStatus.Failure;
            if(user.Status != UserStatusType.CONFIRMED)
                return SignInStatus.RequiresVerification;
//            if (await this.UserManager.IsLockedOutAsync(user.Id).WithCurrentCulture<bool>())
//                return SignInStatus.LockedOut;
            if (await UserManager.CheckPasswordAsync(user, password).WithCurrentCulture())
            {
                await SignInAsync(user, isPersistent, false).WithCurrentCulture();
                return SignInStatus.Success;
            }
//            if (shouldLockout)
//            {
//                IdentityResult identityResult = await this.UserManager.AccessFailedAsync(user.Id).WithCurrentCulture<IdentityResult>();
//                if (await this.UserManager.IsLockedOutAsync(user.Id).WithCurrentCulture<bool>())
//                    return SignInStatus.LockedOut;
//            }
            return SignInStatus.Failure;
        }
    }
}