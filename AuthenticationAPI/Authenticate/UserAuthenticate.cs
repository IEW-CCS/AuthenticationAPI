using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AuthenticationAPI.Authenticate
{
    public class UserInfo
    {
        public string UserName { get; set; }
        public string PassWord { get; set; }

    }
    public class UserAuthenticate : IAuthenticate
    {
        private string _AuthName = "UserAuth";
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;

        public UserAuthenticate(ILogger<UserAuthenticate> logger, IConfiguration configuration)
        {
            Logger = logger;
            Configuration = configuration;
        }
        public string AuthenticateName
        {
            get
            {
                return this._AuthName;
            }
        }


        public bool CheckAuth(object Obj, out string RetMsg)
        {
            UserInfo userinfo = Obj as UserInfo;
            if (userinfo != null)
            {
                string provider = Configuration["ConnectionStrings:Provider"];
                string connectstring = Configuration["ConnectionStrings:DefaultConnection"];
               
                RetMsg = string.Empty;
                AuthBaseDES objDes = new AuthBaseDES();
                string securityPssword = string.Empty;
                if (IsNumandEG(userinfo.UserName) == true && IsNumandEG(userinfo.PassWord) == true)
                {
                    using (var db = new DBContext.MetaDBContext(provider, connectstring))
                    {
                        //securityPssword = objDes.EncryptDES(userinfo.PassWord);
                        securityPssword = userinfo.PassWord;
                        var user = db.auth_info.AsQueryable().Where(o => o.username == userinfo.UserName && o.password == securityPssword).FirstOrDefault();
                        if (user != null)
                        {
                            return true;
                        }
                        else
                        {
                            RetMsg = "UserName and Password Not Match.";
                            return false;
                        }
                    }
                }
                else
                {
                    RetMsg = "UserName and Password obtain illegal characters.";
                    return false;
                }
            }
            else
            {
                RetMsg = "User Info Error.";
                return false;
            }
        }

        private bool IsNumandEG(string word)
        {
            Regex NumandEG = new Regex("[^A-Za-z0-9_.]");
            return !NumandEG.IsMatch(word);
        }
    }
}
