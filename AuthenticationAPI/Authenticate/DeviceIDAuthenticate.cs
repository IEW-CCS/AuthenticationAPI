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
    public class DeviceInfo
    {
        public string SerialNo { get; set; }

    }
    public class DeviceIDAuthenticate : IAuthenticate
    {
        private string _AuthName = "DeviceIDAuth";
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;

        public DeviceIDAuthenticate(ILogger<UserAuthenticate> logger, IConfiguration configuration)
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
            DeviceInfo deviceinfo = Obj as DeviceInfo;
            if (deviceinfo != null)
            {
                string provider = Configuration["ConnectionStrings:Provider"];
                string connectstring = Configuration["ConnectionStrings:DefaultConnection"];
                RetMsg = string.Empty;

                using (var db = new DBContext.MetaDBContext(provider, connectstring))
                {

                    var checkDisplay = db.auth_device.AsQueryable().Where(o => o.device == deviceinfo.SerialNo).FirstOrDefault();
                    if (checkDisplay != null)
                    {
                        return true;
                    }
                    else
                    {
                        RetMsg = "Display Feature code Not Register in System.";
                        return false;
                    }
                }
            }

            else
            {
                RetMsg = "Device Info Error.";
                return false;
            }
        }
    }
}
