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
        static DbContextOptions CreateDbConnection(string providerName, string connectionString)
        {
            //"server= localhost;database=IoTDB;user=root;password=qQ123456"
            DbContextOptionsBuilder optionsBuilder = new DbContextOptionsBuilder();
            switch (providerName)
            {
                case "MS SQL":
                    optionsBuilder.UseSqlServer(connectionString);
                    break;

                case "My SQL":
                    optionsBuilder.UseMySQL(connectionString);
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
        public DbSet<HelloWould> hellowould { get; set; }
    }
}
