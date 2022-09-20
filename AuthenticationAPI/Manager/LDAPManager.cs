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

        private readonly ILogger<LoginController> Logger;
        private readonly IConfiguration Configuration;
        private string _ManagerName = "LDAPManager";
        private DirectoryEntry BaseEntry = null;


        public string ManageName
        {
            get
            {
                return this._ManagerName;
            }
        }

        public LDAPManager(ILogger<LoginController> logger, IConfiguration configuration)
        {
            Logger = logger;       
            Configuration = configuration;
        }


        public bool Init()
        {
            bool InitialResult = false;
            try
            {
                string LDAPPath = Configuration["LDAP:Path"];
                string LDAPUserName = Configuration["LDAP:AdminName"];
                string LDAPPassWord = Configuration["LDAP:AdminPassWord"];
                BaseEntry = new DirectoryEntry(LDAPPath, LDAPUserName, LDAPPassWord, AuthenticationTypes.None);
                using (DirectorySearcher deSearch = new DirectorySearcher(BaseEntry)) //Search query instance
                {
                    SearchResult searchresult = deSearch.FindOne();
                }
                InitialResult = true;
            }
            catch(Exception ex)
            {
                Logger.LogError("LDAP Init Error, Msg = " + ex.Message);
                InitialResult = false;
            }
            return InitialResult;
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
                using (DirectorySearcher deSearch = new DirectorySearcher(BaseEntry)) //Search query instance
                {
                    // deSearch.Filter = "(&(objectClass=organizationalPerson)(cn=" + cnPath + "))"; //Filter by pager (Student number)
                    deSearch.Filter = string.Format("(&(uid={0}))", username); 
                    deSearch.SearchScope = SearchScope.Subtree;
                    SearchResult searchresult = deSearch.FindOne();

                    if (searchresult == null)
                    {
                        result = false;
                        Logger.LogError(string.Format("UserName = {0}, Not Register in LDAP Server.", username));
                    }
                    else
                    {
                        using (DirectoryEntry uEntry = searchresult.GetDirectoryEntry())
                        {
                            uEntry.InvokeSet("userPassword", password);
                            uEntry.CommitChanges();
                            uEntry.Close();
                            result = true;
                            /*
                            foreach (string property in uEntry.Properties.PropertyNames)
                            {
                                string value = uEntry.Properties[property][0].ToString();
                                Logger.LogInformation(property + ":" + value);
                            }*/

                            //uEntry.InvokeSet("mail", "James01@gmail.com");

                        }
                    }
                }
            }
            catch (Exception ex )
            {
                result = false;
                Logger.LogError(string.Format("Modify User Password Error, UserName = {0}, Password = {1}, Exception Message = {2}.",username,password,ex.Message));
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
