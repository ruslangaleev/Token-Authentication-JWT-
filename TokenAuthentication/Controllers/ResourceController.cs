using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace TokenAuthentication.Controllers
{
    [Route("api")]
    public class ResourceController : Controller
    {
        // POST api
        [Authorize(Roles = "user")]
        [HttpPost]
        public IEnumerable<string> Post()
        {
            return new string[] { "value1", "value2" };
        }
    }
}
