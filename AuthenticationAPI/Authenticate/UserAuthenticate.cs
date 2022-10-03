using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AuthenticationAPI.Authenticate
{
    public class UserInfo
    {
        public UserInfo( string username, string password)
        {
            this.UserName = username;
            this.PassWord = password;

        }
        public string UserName { get; }
        public string PassWord { get; }

    }
    public class UserAuthenticate : IAuthenticate
    {
        private readonly IConfiguration Configuration;
        private string Provider = string.Empty;
        private string Connectstring = string.Empty;

        public UserAuthenticate(ILogger<UserAuthenticate> logger, IConfiguration configuration)
        {
            Configuration = configuration;
            Provider = Configuration["ConnectionStrings:Provider"];
            Connectstring = Configuration["ConnectionStrings:DefaultConnection"];
        }
        public string AuthenticateName
        {
            get
            {
                return AuthenticateService.USERINFO.ToString();
            }
        }
        public bool CheckAuth(object Obj, out string RetMsg)
        {
            UserInfo userinfo = Obj as UserInfo;
            RetMsg = string.Empty;
            if (userinfo != null)
            {
                if (Check_illegal(userinfo.UserName) == true && Check_illegal(userinfo.PassWord) == true)
                {
                    using (var db = new DBContext.MetaDBContext(Provider, Connectstring))
                    {
                        var user = db.auth_info.AsQueryable().Where(o => o.username == userinfo.UserName && o.password == DESPassword(userinfo.PassWord)).FirstOrDefault();
                        if (user != null)
                        {
                            return true;
                        }
                        else
                        {
                            RetMsg = "Username and Password Check Mismatch.";
                            return false;
                        }
                    }
                }
                else
                {
                    RetMsg = "Username or Password obtain illegal characters.";
                    return false;
                }
            }
            else
            {
                RetMsg = "User Information Format Error.";
                return false;
            }
        }

        private bool Check_illegal(string word)
        {
            Regex NumandEG = new Regex("[^A-Za-z0-9_.]");
            return !NumandEG.IsMatch(word);
        }

        private string SHA1Password( string password)
        {
            string encrypepassword = string.Empty;
            try
            {
                using var hash = SHA1.Create();
                var byteArray = hash.ComputeHash(Encoding.UTF8.GetBytes(password));
                encrypepassword = Convert.ToHexString(byteArray).ToLower();
            }
            catch
            {
                encrypepassword = string.Empty;
            }
            return encrypepassword;
        }

        private string DESPassword(string password)
        {
            string encrypepassword = string.Empty;
            try
            {
                AuthBaseDES objDes = new AuthBaseDES();
                encrypepassword = objDes.EncryptDES(password);
            }
            catch
            {
                encrypepassword = string.Empty;
            }
            return encrypepassword;
        }
    }
}
