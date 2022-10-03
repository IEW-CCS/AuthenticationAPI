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
        public DeviceInfo(string deviceinfo)
        {
            SerialNo = deviceinfo;
        }
        public string SerialNo { get; }
    }
    public class DeviceIDAuthenticate : IAuthenticate
    {
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private string Provider = string.Empty;
        private string Connectstring = string.Empty;
        public DeviceIDAuthenticate(ILogger<UserAuthenticate> logger, IConfiguration configuration)
        {
            Logger = logger;
            Configuration = configuration;
            Provider = Configuration["ConnectionStrings:Provider"];
            Connectstring = Configuration["ConnectionStrings:DefaultConnection"];
        }
        public string AuthenticateName
        {
            get
            {
                return AuthenticateService.DEVICEID.ToString();
            }
        }

        public bool CheckAuth(object Obj, out string RetMsg)
        {
            DeviceInfo deviceinfo = Obj as DeviceInfo;
            RetMsg = string.Empty;
            if (deviceinfo != null)
            {
                using (var db = new DBContext.MetaDBContext(Provider, Connectstring))
                {
                    var checkDisplay = db.auth_device.AsQueryable().Where(o => o.device == deviceinfo.SerialNo).FirstOrDefault();
                    if (checkDisplay != null)
                    {
                        return true;
                    }
                    else
                    {
                        RetMsg = "Display Code not Register in System.";
                        return false;
                    }
                }
            }
            else
            {
                RetMsg = "Device Info Format Error.";
                return false;
            }
        }
    }
}
