using System;
using System.Configuration;
using System.Threading.Tasks;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Microsoft.AspNet.Identity;

namespace CognitoSampleMVC.Cognito
{
    public class CognitoUserStore : IUserStore<CognitoUser>, 
                                    IUserLockoutStore<CognitoUser, string>, 
                                    IUserTwoFactorStore<CognitoUser, string>
    {
        private readonly AmazonCognitoIdentityProviderClient _client = new AmazonCognitoIdentityProviderClient();
        private readonly string _clientId = ConfigurationManager.AppSettings["CLIENT_ID"];
        private readonly string _poolId = ConfigurationManager.AppSettings["USERPOOL_ID"];
        public void Dispose()
        {
            // TODO: Clean up
        }

        public Task CreateAsync(CognitoUser user)
        {
            // Register the user using Cognito
            var signUpRequest = new SignUpRequest
            {
                ClientId = _clientId,
                Password = user.Password,
                Username = user.Email,

            };

            var emailAttribute = new AttributeType
            {
                Name = "email",
                Value = user.Email
            };
            signUpRequest.UserAttributes.Add(emailAttribute);

            return _client.SignUpAsync(signUpRequest);
        }

        public Task UpdateAsync(CognitoUser user)
        {
            throw new NotImplementedException();
        }

        public Task DeleteAsync(CognitoUser user)
        {
            throw new NotImplementedException();
        }

        public Task<CognitoUser> FindByIdAsync(string userId)
        {
            return FindByNameAsync(userId);
        }

        public Task<CognitoUser> FindByNameAsync(string userName)
        {
            // Register the user using Cognito
            var getUserRequest = new AdminGetUserRequest()
            {
                Username = userName,
                UserPoolId = _poolId
            };

            return FindAsync(userName);

        }

        private async Task<CognitoUser> FindAsync(string userName)
        {
            // Register the user using Cognito
            var getUserRequest = new AdminGetUserRequest()
            {
                Username = userName,
                UserPoolId = _poolId
            };

            try
            {
                var result = await _client.AdminGetUserAsync(getUserRequest);

                return new CognitoUser
                {
                    UserName = result.Username,
                    Status = result.UserStatus
                };
            }
            catch (UserNotFoundException e)
            {
                return null;
            }

        }

        #region IUserLockoutStore
        public Task<DateTimeOffset> GetLockoutEndDateAsync(CognitoUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEndDateAsync(CognitoUser user, DateTimeOffset lockoutEnd)
        {
            throw new NotImplementedException();
        }

        public Task<int> IncrementAccessFailedCountAsync(CognitoUser user)
        {
            throw new NotImplementedException();
        }

        public Task ResetAccessFailedCountAsync(CognitoUser user)
        {
            throw new NotImplementedException();
        }

        public Task<int> GetAccessFailedCountAsync(CognitoUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetLockoutEnabledAsync(CognitoUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEnabledAsync(CognitoUser user, bool enabled)
        {
            return new Task(() => { });
        }
        #endregion IUserLockoutStore

        #region ITwoFactor
        public Task SetTwoFactorEnabledAsync(CognitoUser user, bool enabled)
        {
            return new Task(() => { });
        }

        public Task<bool> GetTwoFactorEnabledAsync(CognitoUser user)
        {
            return new Task<bool>(() => false); // TODO: Fix this up.
        }


        #endregion
    }
}