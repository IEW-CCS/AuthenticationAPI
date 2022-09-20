using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class DeserializeObj
    {
        public static HttpTrx _HttpTrx(string DataContent)
        {
            HttpTrx obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<HttpTrx>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;

        }
        public static ECS _ECS(string DataContent)
        {
            ECS obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<ECS>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APREGREQ _APREGREQ(string DataContent)
        {
            APREGREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APREGREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APREGPLY _APREGPLY(string DataContent)
        {
            APREGPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APREGPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APREGCMP _APREGCMP(string DataContent)
        {
            APREGCMP obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APREGCMP>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static CCREDPLY _CCREDPLY(string DataContent)
        {
            CCREDPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<CCREDPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static DUUIDRPT _DUUIDRPT(string DataContent)
        {
            DUUIDRPT obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<DUUIDRPT>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static DUUIDACK _DUUIDACK(string DataContent)
        {
            DUUIDACK obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<DUUIDACK>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static WSUIDANN _DUUIDANN(string DataContent)
        {
            WSUIDANN obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<WSUIDANN>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }


        public static AVCONREQ _AVCONREQ(string DataContent)
        {
            AVCONREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<AVCONREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static AVCONPLY _AVCONPLY(string DataContent)
        {
            AVCONPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<AVCONPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }

        public static APVRYREQ _APVRYREQ(string DataContent)
        {
            APVRYREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APVRYREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APVRYPLY _APVRYPLY(string DataContent)
        {
            APVRYPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APVRYPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }

        public static APHPWREQ _AHPWREQ(string DataContent)
        {
            APHPWREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APHPWREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APHPWPLY _AHPWPLY(string DataContent)
        {
            APHPWPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APHPWPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }

    }
}
