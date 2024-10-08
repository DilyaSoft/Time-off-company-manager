using Microsoft.Extensions.Options;
using System.Security.Claims;
using TimeOffManager.Core.DTO;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.Core.Services.Interfaces
{
    public interface IAccountService
    {
        public Task<Token> RefreshToken(string token );
        public Task<SignInResult> SignIn(string username, string password );
        public Task<SignUpResult> SignUpOwner(string username, string password, string fName, string lName, 
            DateTime birthDate, string jobTitle);
        public Task<User?> GetIfAuthorized(ClaimsPrincipal currentUser, bool withCompany = false);
        public Task<UpdateResult<User>> UpdateProfile(UpdateProfileDTO toUpdate, User user);
        public Task<User?> GetIdentity(ClaimsPrincipal currentUser);
        public Task<bool> IsOwner(Manager manager);
        public Task UpdateAllowanceTimeOffForUser(int userId, int totalTimeOff, int tookTimeOff);
        public Task SignOut();
        public Task SendInviteToTeam(User user, int teamId);
        public Task<User> CreateDefaultUser(string fName, string lName, string email, int teamId);
        public Task<bool> IsInviteValid(string email);
    }
}
