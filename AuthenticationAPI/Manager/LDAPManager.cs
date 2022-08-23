using AuthenticationAPI;
using AuthenticationAPI.DBContext;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Controllers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.DirectoryServices;

namespace AuthenticationAPI.Manager
{
    public class LDAPManager : IHostedService
    {
        private int count = 0;
        private readonly IQueueManager _QueueManager;
        private readonly IObjectManager _ObjectManager;
        private readonly ILogger<LoginController> _logger;
        private readonly IConfiguration _Configuration;
        private Thread _routineTask = null;
        private string _ManagerName = "LDAPManager";
        private ObjectManager ConstObject;
        private bool _keepRunning = true;


        private string LDAPPath = string.Empty;  
        private string LDAPUserName = string.Empty;
        private string LDAPPassWord = string.Empty;

        public string ManageName
        {
            get
            {
                return this._ManagerName;
            }
        }

        public LDAPManager(ILogger<LoginController> logger, IQueueManager QueueManager, IObjectManager ObjectManager, IConfiguration Configuration)
        {
            _logger = logger;
            _QueueManager = QueueManager;
            _ObjectManager = ObjectManager;
            _Configuration = Configuration;
            Init();
        }


        public void Init()
        {
            ConstObject = (ObjectManager)_ObjectManager.GetInstance;

            LDAPPath = _Configuration["LDAP:Path"];
            LDAPUserName = _Configuration["LDAP:AdminName"];
            LDAPPassWord = _Configuration["LDAP:AdminPassWord"];

        }


        private void RoutineTask()
        {
            while (_keepRunning)
            {
                MessageTrx tmp =  _QueueManager.GetMessage();
                if(tmp != null)
                {
                    _logger.LogInformation("Get Message  = " + tmp.ClientID.ToString());

                    Thread.Sleep(1);
                }
   
                _logger.LogWarning("Count = " + count.ToString());
                count++;
                Thread.Sleep(1000);
            }
        }


        public async Task StartAsync(CancellationToken cancellationToken)
        {
            if (this._routineTask == null)
            {
                this._routineTask = new Thread(new ThreadStart(RoutineTask));
                this._routineTask.IsBackground = true;
                this._routineTask.Start();
            }
            else
            {
                this._routineTask = null;
                this._routineTask = new Thread(new ThreadStart(RoutineTask));
                this._routineTask.IsBackground = true;
                this._routineTask.Start();
            }
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            //Cleanup logic here
            _keepRunning = false;
        }



        private DirectoryEntry GetDirectoryEntry(string path, string username, string password)
        {
            return new DirectoryEntry(path, username, password, AuthenticationTypes.Signing); 
        }

        private bool UserExists(string UserName)
        {
            DirectoryEntry de = GetDirectoryEntry(LDAPPath, LDAPUserName, LDAPPassWord);
            using (DirectorySearcher deSearch = new DirectorySearcher(de)) //Search query instance
            {
                deSearch.Filter = "(&(objectClass=organizationalPerson)(cn= " + UserName + "))"; //Filter by pager (Student number)
                SearchResult searchresult = deSearch.FindOne();
                using (DirectoryEntry uEntry = searchresult.GetDirectoryEntry())
                {
                    string sn = uEntry.Properties["sn"].Value.ToString(); //Store full student name in string
                    string Description = uEntry.Properties["description"].Value.ToString();

                }
            }
            return true;
        }
    }
}
