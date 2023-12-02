using AuthServices.Model.Account;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthServices.DbContext
{
    public class AppDataContext:IdentityDbContext<UserModel>
    {
        public AppDataContext(DbContextOptions<AppDataContext> options) : base(options) { }
    }
}
