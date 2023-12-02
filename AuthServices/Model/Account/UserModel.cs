using Microsoft.AspNetCore.Identity;

namespace AuthServices.Model.Account
{
    public class UserModel:IdentityUser
    {
        public string? FirstName { get;set; }
        public string? LastName { get;set;}
    }
}
