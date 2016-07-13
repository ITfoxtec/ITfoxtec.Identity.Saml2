using Microsoft.AspNetCore.Mvc;

namespace TestIdPCore.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
