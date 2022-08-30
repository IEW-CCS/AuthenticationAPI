using AuthenticationAPI.DtoS;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Kernel
{
    public class ObjectManager : IObjectManager
    {

        private readonly ILogger _logger;
        private  ConcurrentDictionary<string, CREDINFO> CredInfo = null;
        private  ConcurrentDictionary<string, string> DeviceUUID = null;


        public ObjectManager(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<ObjectManager>();
            Init();
        }

        public object GetInstance
        {
            get
            {
                return this;
            }

        }

        private void Init()
        {
            CredInfo = new ConcurrentDictionary<string, CREDINFO>();
        }

        public CREDINFO GetCredInfo(string Key)
        {
            return this.CredInfo.GetOrAdd(Key, new CREDINFO());
        }

        public void SetCredInfo(string Key, CREDINFO Obj)
        {
            this.CredInfo.AddOrUpdate(Key, Obj, (key, oldvalue) => Obj);
        }

        public string GetDeviceUUID(string Key)
        {
            return this.DeviceUUID.GetOrAdd(Key, key =>
            {
                return string.Empty;
            });
        }

        public void SetDeviceUUID(string Key, string uuid)
        {
            this.DeviceUUID.AddOrUpdate(Key, uuid, (key, oldvalue) => uuid);
        }

    }
}
