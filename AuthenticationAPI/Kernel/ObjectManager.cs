using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Kernel
{
    public class ObjectManager : IObjectManager
    {

        private readonly ILogger _logger;
        private string _DBType = string.Empty;
        private string _DBConnectString = string.Empty;
         
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

            var builder = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile("appsettings.json");
            var config = builder.Build();
            _DBType = config.GetConnectionString("Type1") ?? "My SQL"  ;
            _DBConnectString = config.GetConnectionString("DefaultConnection") ?? "server=localhost;port=3306;database=hello_db;uid=root;password=qQ123456";

        }

        public string DB_Type
        {
            get
            {
                return this._DBType;
            }

        }

        public string DB_ConnectString
        {
            get
            {
                return this._DBConnectString;
            }

        }


    }
}
