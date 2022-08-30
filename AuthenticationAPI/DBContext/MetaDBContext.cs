using AuthenticationAPI.DBContext;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace AuthenticationAPI.DBContext
{
    public class MetaDBContext : DbContext
    {
        static DbContextOptions CreateDbConnection( string Provider, string ConnectionString)
        {
            //"server= localhost;database=IoTDB;user=root;password=qQ123456"
            DbContextOptionsBuilder optionsBuilder = new DbContextOptionsBuilder();
            switch (Provider)
            {
                case "MS_SQL":
                    optionsBuilder.UseSqlServer(ConnectionString);
                    break;

                case "MY_SQL":
                    optionsBuilder.UseMySQL(ConnectionString);
                    break;

                default:
                    break;
            }
            return optionsBuilder.Options;
        }

        // Constructor 
        public MetaDBContext(string provider, string connectstring) : base(CreateDbConnection(provider, connectstring))
        {
            base.ChangeTracker.AutoDetectChangesEnabled = false;
            base.ChangeTracker.LazyLoadingEnabled = false;
        }

        public MetaDBContext(DbContextOptions<MetaDBContext> options) : base(options)
        {
            // This is Method Use by Http Used;
            base.ChangeTracker.AutoDetectChangesEnabled = false;
            base.ChangeTracker.LazyLoadingEnabled = false;
        }
        public DbSet<AUTH_CONF> auth_conf { get; set; }
        public DbSet<AUTH_INFO> auth_info { get; set; }
        public DbSet<AUTH_SECURITY> auth_security { get; set; }
    }
}
