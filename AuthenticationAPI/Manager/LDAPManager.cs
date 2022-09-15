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
using System.Text.Json;

namespace AuthenticationAPI.Manager
{
    public class LDAPManager : ILDAPManagement
    {
        private int count = 0;
        private readonly IQueueManager QueueManager;
        private readonly IObjectManager ObjectManager;
        private readonly ILogger<LoginController> Logger;
        private readonly IConfiguration Configuration;
        private Thread _routineTask = null;
        private string _ManagerName = "LDAPManager";
        private bool _keepRunning = true;
        private DirectoryEntry entry = null;
        private readonly ISecurityManager SecurityManager;



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

        public LDAPManager(ILogger<LoginController> logger, IQueueManager queuemanager, IObjectManager objectmanager, IConfiguration configuration, ISecurityManager securitymanager)
        {
            Logger = logger;
            QueueManager = queuemanager;
            ObjectManager = objectmanager;
            Configuration = configuration;
            SecurityManager = securitymanager;
            Init();
        }


        public void Init()
        {
            try
            {
                LDAPPath = Configuration["LDAP:Path"];
                LDAPUserName = Configuration["LDAP:AdminName"];
                LDAPPassWord = Configuration["LDAP:AdminPassWord"];
                entry = new DirectoryEntry(LDAPPath, LDAPUserName, LDAPPassWord, AuthenticationTypes.None);
                using (DirectorySearcher deSearch = new DirectorySearcher(entry)) //Search query instance
                {
                    SearchResult searchresult = deSearch.FindOne();
                }
            }
            catch(Exception ex)
            {
                Logger.LogError("LDAP Init Error, Msg = " + ex.Message);
            }

        }


        private string GenerateCredential(string username)
        {
            // Testing 
            AuthenticationAPI.DtoS.CREDINFO credInfo = new AuthenticationAPI.DtoS.CREDINFO();
            credInfo.UserName = "james001";
            credInfo.APPGuid = "Enter";
            credInfo.APPVersion = "1.0.0.0";
            credInfo.Nonce = 0;

      

            string credJsonStr = JsonSerializer.Serialize(credInfo);
            string signOut = string.Empty;
            string signOut1 = string.Empty;
            string signOut2 = string.Empty;


            int i1 = SecurityManager.SIGNRSASecurity().SignString(credJsonStr, out signOut1, out string returnMsgOut1);

           int i2 = SecurityManager.SIGNRSASecurity().SignString(credJsonStr, out signOut2, out string returnMsgOut2);


            int r1 = SecurityManager.SIGNRSASecurity().CheckSignString(credJsonStr, signOut1, out string checkReturn1);

            int r2 = SecurityManager.SIGNRSASecurity().CheckSignString(credJsonStr, signOut2, out string checkReturn2);


            string Credential = string.Empty;
            if (SecurityManager.SIGNRSASecurity().SignString(credJsonStr, out signOut, out string returnMsgOut) == 0)
            {
                Credential = signOut;
            }
            else
            {
                Credential = string.Empty;
            }
            return Credential;
        }





        private DirectoryEntry GetDirectoryEntry(string path, string username, string password)
        {
            return new DirectoryEntry(path, username, password, AuthenticationTypes.Signing);
        }

        public bool ModifyUserPassword(string username, string password)
        {
            bool result = false;

            try
            {
                //DirectoryEntry de = GetDirectoryEntry(LDAPPath, LDAPUserName, LDAPPassWord);
                using (DirectorySearcher deSearch = new DirectorySearcher(entry)) //Search query instance
                {
                    // deSearch.Filter = "(&(objectClass=organizationalPerson)(cn=" + cnPath + "))"; //Filter by pager (Student number)
                    deSearch.Filter = string.Format("(&(uid={0}))", username); 
                    deSearch.SearchScope = SearchScope.Subtree;
                    SearchResult searchresult = deSearch.FindOne();
                    using (DirectoryEntry uEntry = searchresult.GetDirectoryEntry())
                    {

                        foreach (string property in uEntry.Properties.PropertyNames)
                        {
                            string value = uEntry.Properties[property][0].ToString();

                            Logger.LogInformation(property + ":" + value);
       
                        }

                        uEntry.InvokeSet("mail", "James01@gmail.com");
                        uEntry.InvokeSet("userPassword", "HelloJames");

                        uEntry.CommitChanges();
                        uEntry.Close();



                        // SetPassword(uEntry, password);
                        result = true;
                    }
                }
            }
            catch (Exception ex )
            {
                result = false;
            }

            return result;
        }

     


        /*
        private void RoutineTask()
        {
            while (_keepRunning)
            {
                MessageTrx tmp =  QueueManager.GetMessage();
                if(tmp != null)
                {
                    Logger.LogInformation("Get Message  = " + tmp.ClientID.ToString());

                    Thread.Sleep(1);
                }
   
                Logger.LogWarning("Count = " + count.ToString());
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
        }*/
    }
}
