using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class DeserializeObj
    {

        public static HttpECS _HttpECS(string DataContent)
        {
            HttpECS HttpECS = null;
            try
            {
                HttpECS = JsonSerializer.Deserialize<HttpECS>(DataContent);
            }
            catch
            {
                HttpECS = null;
            }
            return HttpECS;
        }


        public static APREGREQ _APREGREQ(string DataContent)
        {
            APREGREQ apreqreg = null;
            try
            {
                apreqreg = JsonSerializer.Deserialize<APREGREQ>(DataContent);
            }
            catch
            {
                apreqreg = null;
            }
            return apreqreg;
        }

        public static CCREDREQ _CCREDREQ(string DataContent)
        {
            CCREDREQ ccredreq = null;
            try
            {
                ccredreq = JsonSerializer.Deserialize<CCREDREQ>(DataContent);
            }
            catch
            {
                ccredreq = null;
            }
            return ccredreq;
        }

        public static DUUIDRPT _DUUIDRPT(string DataContent)
        {
            DUUIDRPT uuidrpt = null;
            try
            {
                uuidrpt = JsonSerializer.Deserialize<DUUIDRPT>(DataContent);
            }
            catch
            {
                uuidrpt = null;
            }
            return uuidrpt;
        }

        public static APREGCMP _APREGCMP(string DataContent)
        {
            APREGCMP apregcmp = null;
            try
            {
                apregcmp = JsonSerializer.Deserialize<APREGCMP>(DataContent);
            }
            catch
            {
                apregcmp = null;
            }
            return apregcmp;
        }
    }
}
