using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using TokenAuthentication.Models;
using TokenAuthentication.Resource;

namespace TokenAuthentication.Controllers
{
    [Authorize]
    [Route("api/auth")]
    public class AuthorizationController : Controller
    {
        private static ApplicationUser[] users = new ApplicationUser[]
        {
            new ApplicationUser(Guid.NewGuid(), "user")
        };

        private static string _refreshToken;

        /// <summary>
        /// Создает токен для доступа к ресурсам
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("token")]
        public AuthorizationTokenResource GetToken()
        {
            var user = users.FirstOrDefault();

            return GenerateToken(user.UserId.ToString(), user.Role);
        }

        /// <summary>
        /// Создает новый токен для доступа к ресурсам
        /// </summary>
        // Example: In request header use "Bearer <refreshToken>"
        [HttpPost("refreshtoken")]
        public object RefreshToken()
        {
            var userFromClaim = User.Claims.FirstOrDefault(t => t.Type == ClaimsIdentity.DefaultNameClaimType)?.Value;
            if (userFromClaim == null)
                return BadRequest("Не найден идентификатор пользователя");

            var user = users.FirstOrDefault(t => t.UserId.ToString() == userFromClaim);
            if (user == null)
            {
                return BadRequest("Указанный пользовтаель не существует");
            }
            
            return GenerateToken(user.UserId.ToString(), user.Role);
        }

        private AuthorizationTokenResource GenerateToken(string userId, string role)
        {
            var (generatedAccessToken, expires) = GetAccessToken(userId, role);
            var generatedRefreshToken = GetRefreshToken(userId);

            return new AuthorizationTokenResource
            {
                AccessToken = generatedAccessToken,
                ExpiresIn = expires,
                RefreshToken = generatedRefreshToken
            };
        }

        private (string, TimeSpan) GetAccessToken(string userId, string role)
        {
            Claim[] claims = new Claim[]
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, userId),
                new Claim(ClaimsIdentity.DefaultRoleClaimType, role)
            };

            var expires = TimeSpan.FromMinutes(AuthOptions.LIFETIME);
            var now = DateTime.UtcNow;
            // создаем JWT-токен
            var accessToken = new JwtSecurityToken(
                    issuer: AuthOptions.ISSUER,
                    audience: AuthOptions.AUDIENCE,
                    notBefore: now,
                    claims: claims,
                    expires: now.Add(expires),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
            return (new JwtSecurityTokenHandler().WriteToken(accessToken), expires);
        }

        private string GetRefreshToken(string userId)
        {
            Claim[] claims = new Claim[]
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, userId)
            };

            var now = DateTime.UtcNow;
            var refreshToken = new JwtSecurityToken(
                    issuer: AuthOptions.ISSUER,
                    audience: AuthOptions.AUDIENCE,
                    notBefore: now,
                    claims: claims,
                    expires: now.Add(TimeSpan.FromMinutes(30)),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
            var encodedRefreshJwt = new JwtSecurityTokenHandler().WriteToken(refreshToken);

            // Записать в кэш
            _refreshToken = encodedRefreshJwt;

            return encodedRefreshJwt;
        }
    }
}
