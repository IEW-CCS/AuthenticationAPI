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
        public static ARREGREQ _APREGREQ(string DataContent)
        {
            ARREGREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<ARREGREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static ARREGPLY _APREGPLY(string DataContent)
        {
            ARREGPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<ARREGPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static ARREGCMP _APREGCMP(string DataContent)
        {
            ARREGCMP obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<ARREGCMP>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static CRCRLPLY _CCREDPLY(string DataContent)
        {
            CRCRLPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<CRCRLPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static CRUIDRPT _DUUIDRPT(string DataContent)
        {
            CRUIDRPT obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<CRUIDRPT>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static CRUIDPLY _DUUIDACK(string DataContent)
        {
            CRUIDPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<CRUIDPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static ARWSCANN _DUUIDANN(string DataContent)
        {
            ARWSCANN obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<ARWSCANN>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }


        public static AACONREQ _AVCONREQ(string DataContent)
        {
            AACONREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<AACONREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static AACONPLY _AVCONPLY(string DataContent)
        {
            AACONPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<AACONPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }

        public static AAUTHREQ _APVRYREQ(string DataContent)
        {
            AAUTHREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<AAUTHREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static AAUTHPLY _APVRYPLY(string DataContent)
        {
            AAUTHPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<AAUTHPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }

        public static AAPSWREQ _AHPWREQ(string DataContent)
        {
            AAPSWREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<AAPSWREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static AAPSWPLY _AHPWPLY(string DataContent)
        {
            AAPSWPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<AAPSWPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }

    }
}
