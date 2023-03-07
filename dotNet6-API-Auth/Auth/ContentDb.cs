using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace dotNet6_API_Auth.Auth;

public class ContentDb : IdentityDbContext<IdentityUser>
{ 
    public ContentDb(DbContextOptions<ContentDb> options) : base(options)
    {
        
    }
    
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
    }
}