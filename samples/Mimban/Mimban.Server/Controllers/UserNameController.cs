using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using System.Reflection.Metadata;
using System.Security.Claims;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;
namespace Mimban.Server;

public record Username(string value);

[ApiController]
//[Route("[controller]")]
[Route("username")]
public class UserNameController : Controller
{
    [HttpGet]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public Task<ActionResult<string>> GetUserName()
    {
        
        var userName = User.Identity!.Name;
        if (string.IsNullOrEmpty(userName))
        {
            return Task.FromResult<ActionResult<string>>(("User name not found."));
        }
        return Task.FromResult<ActionResult<string>>((userName ?? ""));
        
    }
}