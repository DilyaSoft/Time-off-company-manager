using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using TimeOffManager.Core.DTO;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.Core.Settings;
using TimeOffManager.DataAccess;
using TimeOffManager.DataAccess.Context;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.Core.Services
{
    public class AccountService(
        UserManager<User> usersService,
        SignInManager<User> signInManager,
        IOptions<JwtOptions> options,
        IEmailService emailService,
        DataContext dataContext) : IAccountService
    {
        public async Task<User?> GetIfAuthorized(ClaimsPrincipal currentUser, bool withCompany = false)
        {
            if (currentUser is not { Identity: not null }) return null;
            
            var identity = await GetIdentity(currentUser);
            if (identity == null) return null;
            var users = dataContext.Users.Include(x => x.Team)
                .AsQueryable();
            // if (withCompany)
            // {
            //     users = users.Include(x => x.Company);
            // }
            var user = await users.FirstOrDefaultAsync(x => x.Id == identity.Id);
            return user ?? null;
        }

        public async Task<User?> GetIdentity(ClaimsPrincipal currentUser)
        {
            if (currentUser == null)
            {
                return null;
            }

            return await usersService.GetUserAsync(currentUser);
        }

        public async Task<Token> RefreshToken(string token)
        {
            var principal = GetPrincipal(token, isAccessToken: false);
            var identity = await GetIdentity(principal);
            var manager = new JwtManager(options);
            var newToken = manager.GenerateToken(identity.Id);
            return newToken;
        }

        private ClaimsPrincipal GetPrincipal(string token, bool isAccessToken = true)
        {
            var key = new SymmetricSecurityKey(isAccessToken ? options.Value.AccessSecret : options.Value.RefreshSecret);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = options.Value.Issuer,
                ValidAudience = options.Value.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        public async Task<DTO.SignInResult> SignIn(string username, string password)
        {
            var exists = await usersService.FindByNameAsync(username);

            if (exists == null)
            {
                return DTO.SignInResult.Error("Provided email was not found as registered");
            }
            var checkPassword = await signInManager.PasswordSignInAsync(exists, password, false, false);

            if (!checkPassword.Succeeded)
            {
                return DTO.SignInResult.Error("Password isn't correct");
            }

            var manager = new JwtManager(options);
            var token = manager.GenerateToken(exists.Id);

            return DTO.SignInResult.Ok(token);
        }

        public async Task<SignUpResult> SignUpOwner(string username, string password, string fName, string lName,
            DateTime birthDate, string jobTitle)
        {
            var exists = await usersService.FindByEmailAsync(username);
            if (exists != null)
            {
                return SignUpResult.Error("Provided email has already registered");
            }

            var defaultCompany = new Company()
            {
                Name = "Default"
            };
            await dataContext.Companies.AddAsync(defaultCompany);
            await dataContext.SaveChangesAsync();
            
            var manager = new Manager()
            {
                UserName = username,
                Email = username,
                StartWorkDate = DateTime.UtcNow,
                BirthDate = birthDate,
                FirstName = fName,
                LastName = lName,
                JobTitle = jobTitle,
                CompanyId = defaultCompany.Id
            };
            var result = await usersService.CreateAsync(manager);

            if (!result.Succeeded)
            {
                SignUpResult.Error(string.Join(',', result.Errors.Select(x => x.Description)));
            }

            var setPassword = await usersService.AddPasswordAsync(manager, password);
            if (!setPassword.Succeeded)
            {
                return SignUpResult.Error(string.Join(',', setPassword.Errors.Select(x => x.Description)));
            }

            var addRole = await usersService.AddToRoleAsync(manager, DbConstants.OwnerRoleName);

            if (!addRole.Succeeded)
            {
                return SignUpResult.Error(string.Join(',', addRole.Errors.Select(x => x.Description)));
            }
            
            var jwt = new JwtManager(options);
            var token = jwt.GenerateToken(manager.Id);
            
            return SignUpResult.Ok(token);
        }

        public async Task<UpdateResult<User>> UpdateProfile(UpdateProfileDTO toUpdate, User user)
        {
            user.FirstName = toUpdate.FirstName;
            user.LastName = toUpdate.LastName;
            user.Email = toUpdate.Email;
            user.BirthDate = toUpdate.BirthDate;
            await dataContext.SaveChangesAsync();
            return UpdateResult<User>.Ok(user);
        }

        public async Task<bool> IsOwner(Manager manager)
        {
            var isrole = await usersService.IsInRoleAsync(manager, DbConstants.OwnerRoleName);
            return isrole;
        }

        public async Task SignOut()
        {
            await signInManager.SignOutAsync();
        }

        public async Task UpdateAllowanceTimeOffForUser(int userId, int totalTimeOff, int tookTimeOff)
        {
            var user = await dataContext.Users.FindAsync(userId);
            user.TotalAllowanceTimeOffInYear = totalTimeOff;
            user.TookAllowanceTimeOff = tookTimeOff;
            await dataContext.SaveChangesAsync();
        }

        public async Task SendInviteToTeam(User user, int teamId)
        {
            var resetToken = await usersService.GeneratePasswordResetTokenAsync(user);
            var link = $"http://localhost:5173/accept-invite?token={resetToken}&email={user.Email}&fName={user.FirstName}&lName={user.LastName}";
            var message = $"Follow the link to accept invite to the team. Link: {link}";
            await emailService.Send(user.Email, SmtpSettings.From, message, "Accept invite to your team's workspace!");
        }

        public async Task<User> CreateDefaultUser(string fName, string lName, string email, int teamId)
        {
            var defaultPassword = "defaultPass12345$%==++===,";
            var user = new User()
            {
                UserName = email,
                FirstName = fName,
                LastName = lName,
                Email = email,
                InviteStatus = DataAccess.Enums.InviteStatus.WaitForAccept,
                TeamId = teamId,
                RoleName = "User"
            };

            await usersService.CreateAsync(user, defaultPassword);

            var setPassword = await usersService.AddPasswordAsync(user, defaultPassword);


            return user;
        }

        public async Task<bool> IsInviteValid(string email)
        {
            var user = await dataContext.Users.FirstOrDefaultAsync(x => x.UserName == email);
            return user != null && user.TeamId != 0 && user.InviteStatus == DataAccess.Enums.InviteStatus.WaitForAccept; 
        }
    }
}
