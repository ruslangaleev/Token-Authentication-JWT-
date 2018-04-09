using System;

namespace TokenAuthentication.Models
{
    public class ApplicationUser
    {
        public Guid UserId { get; set; }

        public string Role { get; set; }

        public ApplicationUser() { }

        public ApplicationUser(Guid userId, string role)
        {
            UserId = userId;
            Role = role;
        }
    }
}
