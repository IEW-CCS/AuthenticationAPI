using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthenticationAPI.Middleware
{
    public class JwtBearerBacker
    {
        public JwtBearerOptions Options { get; private set; }
        public JwtBearerBacker(JwtBearerOptions options)
        {
            this.Options = options;
        }

        public bool IsJwtValid(string token)
        {
            List<Exception> validationFailures = null;
            Microsoft.IdentityModel.Tokens.SecurityToken validatedToken;
            foreach (var validator in Options.SecurityTokenValidators)
            {
                if (validator.CanReadToken(token))
                {
                    ClaimsPrincipal principal;
                    try
                    {
                        principal = validator.ValidateToken(token, Options.TokenValidationParameters, out validatedToken);
                    }
                    catch (Exception ex)
                    {
                        // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the event.
                        if (Options.RefreshOnIssuerKeyNotFound && Options.ConfigurationManager != null
                            && ex is SecurityTokenSignatureKeyNotFoundException)
                        {
                            Options.ConfigurationManager.RequestRefresh();
                        }

                        if (validationFailures == null)
                            validationFailures = new List<Exception>(1);
                        validationFailures.Add(ex);
                        continue;
                    }
                    return true;
                }
            }
            return false;
        }

        public string JetUserName(string tokenString)
        {
            var token = new JwtSecurityToken( jwtEncodedString : tokenString);
            var UserName = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.NameId);
            if(UserName == null)
            {
                return string.Empty;
            }
            else
            {
                return UserName.Value;
            }
                
        }
    }
}
