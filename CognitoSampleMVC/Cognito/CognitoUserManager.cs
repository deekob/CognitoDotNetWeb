using System;
using System.Configuration;
using System.Threading.Tasks;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;

namespace CognitoSampleMVC.Cognito
{
    public class CognitoUserManager : UserManager<CognitoUser>
    {

        private readonly AmazonCognitoIdentityProviderClient _client = new AmazonCognitoIdentityProviderClient();
        private readonly string _clientId = ConfigurationManager.AppSettings["CLIENT_ID"];
        private readonly string _poolId = ConfigurationManager.AppSettings["USERPOOL_ID"];

        public CognitoUserManager(IUserStore<CognitoUser> store)
            : base(store)
        {
        }

        public static CognitoUserManager Create(IdentityFactoryOptions<CognitoUserManager> options, IOwinContext context)
        {
            var manager = new CognitoUserManager(new CognitoUserStore());
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<CognitoUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                //RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = false;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<CognitoUser>
            {
                MessageFormat = "Your security code is {0}"
            });
            manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<CognitoUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });
            manager.EmailService = new EmailService();
            manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<CognitoUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }

        public override Task<bool> CheckPasswordAsync(CognitoUser user, string password)
        {
            return CheckPasswordAsync(user.UserName, password);
        }

        private async Task<bool> CheckPasswordAsync(string userName, string password)
        {
            try
            {
                var client = new AmazonCognitoIdentityProviderClient();

                var authReq = new AdminInitiateAuthRequest
                {
                    UserPoolId = ConfigurationManager.AppSettings["USERPOOL_ID"],
                    ClientId = ConfigurationManager.AppSettings["CLIENT_ID"],
                    AuthFlow = AuthFlowType.ADMIN_NO_SRP_AUTH
                };
                authReq.AuthParameters.Add("USERNAME", userName);
                authReq.AuthParameters.Add("PASSWORD", password);

                AdminInitiateAuthResponse authResp = await client.AdminInitiateAuthAsync(authReq);

                // Validate that there is no case that an exception won't be thrown

                return true;
            }
            catch
            {
                return false;
            }
        }

        public override async Task<IdentityResult> ConfirmEmailAsync(string username, string code)
        {
            // Register the user using Cognito
            var confirmSignUpRequest = new ConfirmSignUpRequest
            {
                ClientId = _clientId,
                ConfirmationCode = code,
                Username = username
            };

            try
            {

                var result = await _client.ConfirmSignUpAsync(confirmSignUpRequest);

                return IdentityResult.Success;
            }
            catch (Exception e)
            {
                return IdentityResult.Failed(e.Message);
            }
        }

        public async Task<bool> SendForgotPasswordEmailAsync(string username)
        {
            var forgotPasswordRequest = new ForgotPasswordRequest()
            {
                ClientId = _clientId,
                Username = username
            };

            try
            {

                var result = await _client.ForgotPasswordAsync(forgotPasswordRequest);

                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        public new async Task<bool> ResetPasswordAsync(string username, string code, string password)
        {
            var forgotPasswordRequest = new ConfirmForgotPasswordRequest()
            {
                ClientId = _clientId,
                Username = username,
                ConfirmationCode = code,
                Password = password
            };

            try
            {

                var result = await _client.ConfirmForgotPasswordAsync(forgotPasswordRequest);

                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }
    }
}